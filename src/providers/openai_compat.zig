const std = @import("std");
const provider = @import("provider.zig");

pub const OpenAiCompatProvider = struct {
    base_url: []const u8,
    api_key: []const u8, // may be empty (for local endpoints)
    api_key_env: []const u8,

    pub fn init(a: std.mem.Allocator, base_url: []const u8, api_key: []const u8, api_key_env: []const u8) !OpenAiCompatProvider {
        return .{
            .base_url = try a.dupe(u8, base_url),
            .api_key = try a.dupe(u8, api_key),
            .api_key_env = try a.dupe(u8, api_key_env),
        };
    }

    pub fn deinit(self: *OpenAiCompatProvider, a: std.mem.Allocator) void {
        a.free(self.base_url);
        a.free(self.api_key);
        a.free(self.api_key_env);
    }

    pub fn chat(self: OpenAiCompatProvider, a: std.mem.Allocator, req: provider.ChatRequest) !provider.ChatResponse {
        // Build a single system message containing system + memory items for simplicity.
        const sys = try buildSystemMessage(a, req.system, req.memory_context);
        defer a.free(sys);

        const url = try std.fmt.allocPrint(a, "{s}/chat/completions", .{std.mem.trimRight(u8, self.base_url, "/")});
        defer a.free(url);

        const body = try buildRequestBody(a, req.model, req.temperature, sys, req.user);
        defer a.free(body);

        var client = std.http.Client{ .allocator = a };
        defer client.deinit();

        var headers = std.http.Headers.init(a);
        defer headers.deinit();

        try headers.append("content-type", "application/json");
        try headers.append("accept", "application/json");

        const api_key = if (self.api_key.len > 0) self.api_key else (std.process.getEnvVarOwned(a, self.api_key_env) catch "");
        defer if (self.api_key.len == 0 and api_key.len > 0) a.free(api_key);

        if (api_key.len > 0) {
            const auth = try std.fmt.allocPrint(a, "Bearer {s}", .{api_key});
            defer a.free(auth);
            try headers.append("authorization", auth);
        }

        const uri = try std.Uri.parse(url);

        var req_http = try client.open(.POST, uri, headers, .{});
        defer req_http.deinit();

        req_http.transfer_encoding = .{ .content_length = body.len };

        try req_http.send();
        try req_http.writeAll(body);
        try req_http.finish();
        try req_http.wait();

        if (req_http.response.status != .ok) {
            const err_body = try readAllCapped(a, req_http.reader(), 128 * 1024);
            defer a.free(err_body);
            std.log.err("provider http status={d} body={s}", .{@intFromEnum(req_http.response.status), err_body});
            return error.ProviderHttpError;
        }

        const resp_bytes = try readAllCapped(a, req_http.reader(), 4 * 1024 * 1024);
        defer a.free(resp_bytes);

        const content = try parseChatCompletionContentAlloc(a, resp_bytes);
        return .{ .content = content };
    }
};

fn buildSystemMessage(a: std.mem.Allocator, system: ?[]const u8, memory: []const provider.MemoryItem) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();

    if (system) |s| {
        try out.writer().writeAll(s);
        try out.writer().writeAll("\n");
    }
    if (memory.len > 0) {
        try out.writer().writeAll("\n[Memory]\n");
        for (memory) |m| {
            try out.writer().print("- {s}: {s}\n", .{m.title, m.snippet});
        }
    }
    return try out.toOwnedSlice();
}

fn buildRequestBody(a: std.mem.Allocator, model: []const u8, temp: f64, system: []const u8, user: []const u8) ![]u8 {
    var stream = std.json.StringifyStream.init(a);
    defer stream.deinit();

    try stream.beginObject();
    try stream.objectField("model"); try stream.write(model);
    try stream.objectField("temperature"); try stream.write(temp);

    try stream.objectField("messages");
    try stream.beginArray();
    // system
    try stream.beginObject();
    try stream.objectField("role"); try stream.write("system");
    try stream.objectField("content"); try stream.write(system);
    try stream.endObject();

    // user
    try stream.beginObject();
    try stream.objectField("role"); try stream.write("user");
    try stream.objectField("content"); try stream.write(user);
    try stream.endObject();

    try stream.endArray();

    try stream.objectField("stream"); try stream.write(false);
    try stream.endObject();

    return try stream.toOwnedSlice();
}

fn parseChatCompletionContentAlloc(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ta = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, ta, bytes, .{}) catch return error.InvalidJson;
    const root = parsed.value;

    // choices[0].message.content
    const choices = root.object.get("choices") orelse return error.InvalidResponse;
    if (choices != .array or choices.array.items.len == 0) return error.InvalidResponse;
    const first = choices.array.items[0];
    const msg = first.object.get("message") orelse return error.InvalidResponse;
    const content_v = msg.object.get("content") orelse return error.InvalidResponse;
    if (content_v != .string) return error.InvalidResponse;

    return try a.dupe(u8, content_v.string);
}

fn readAllCapped(a: std.mem.Allocator, r: anytype, cap: usize) ![]u8 {
    var buf = std.ArrayList(u8).init(a);
    errdefer buf.deinit();

    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = try r.read(&tmp);
        if (n == 0) break;
        if (buf.items.len + n > cap) return error.ResponseTooLarge;
        try buf.appendSlice(tmp[0..n]);
    }
    return try buf.toOwnedSlice();
}
