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

    pub fn chat(self: OpenAiCompatProvider, a: std.mem.Allocator, io: std.Io, req: provider.ChatRequest) !provider.ChatResponse {
        const sys = try buildSystemMessage(a, req.system, req.memory_context);
        defer a.free(sys);

        const url = try std.fmt.allocPrint(a, "{s}/chat/completions", .{std.mem.trimEnd(u8, self.base_url, "/")});
        defer a.free(url);

        const body = try buildRequestBody(a, req.model, req.temperature, sys, req.user);
        defer a.free(body);

        // Resolve API key: prefer inline, fall back to env var
        const env_key_z = try a.dupeZ(u8, self.api_key_env);
        defer a.free(env_key_z);
        const api_key: []const u8 = if (self.api_key.len > 0)
            self.api_key
        else if (std.c.getenv(env_key_z)) |k|
            std.mem.span(k)
        else
            "";

        // Build curl argv
        var argv_list = std.array_list.Managed([]const u8).init(a);
        defer argv_list.deinit();

        try argv_list.append("curl");
        try argv_list.append("-s");
        try argv_list.append("-X");
        try argv_list.append("POST");
        try argv_list.append("-H");
        try argv_list.append("Content-Type: application/json");
        try argv_list.append("-H");
        try argv_list.append("Accept: application/json");

        var auth_header: ?[]u8 = null;
        defer if (auth_header) |h| a.free(h);

        if (api_key.len > 0) {
            auth_header = try std.fmt.allocPrint(a, "Authorization: Bearer {s}", .{api_key});
            try argv_list.append("-H");
            try argv_list.append(auth_header.?);
        }
        try argv_list.append("-d");
        try argv_list.append(body);
        try argv_list.append(url);

        var child = try std.process.spawn(io, .{
            .argv = argv_list.items,
            .stdout = .pipe,
            .stderr = .pipe,
        });

        var stdout_buf: [4096]u8 = undefined;
        var stdout_reader = child.stdout.?.reader(io, &stdout_buf);
        const resp_bytes = try stdout_reader.interface.allocRemaining(a, std.Io.Limit.limited(4 * 1024 * 1024));
        defer a.free(resp_bytes);

        _ = try child.wait(io);

        if (resp_bytes.len == 0) {
            return error.ProviderHttpError;
        }

        const content = try parseChatCompletionContentAlloc(a, resp_bytes);
        return .{ .content = content };
    }
};

fn buildSystemMessage(a: std.mem.Allocator, system: ?[]const u8, memory: []const provider.MemoryItem) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();

    if (system) |s| {
        try aw.writer.writeAll(s);
        try aw.writer.writeAll("\n");
    }
    if (memory.len > 0) {
        try aw.writer.writeAll("\n[Memory]\n");
        for (memory) |m| {
            try aw.writer.print("- {s}: {s}\n", .{ m.title, m.snippet });
        }
    }
    return try aw.toOwnedSlice();
}

fn buildRequestBody(a: std.mem.Allocator, model: []const u8, temp: f64, system: []const u8, user: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("model");
    try stream.write(model);
    try stream.objectField("temperature");
    try stream.write(temp);

    try stream.objectField("messages");
    try stream.beginArray();
    // system
    try stream.beginObject();
    try stream.objectField("role");
    try stream.write("system");
    try stream.objectField("content");
    try stream.write(system);
    try stream.endObject();

    // user
    try stream.beginObject();
    try stream.objectField("role");
    try stream.write("user");
    try stream.objectField("content");
    try stream.write(user);
    try stream.endObject();

    try stream.endArray();

    try stream.objectField("stream");
    try stream.write(false);
    try stream.endObject();

    return try aw.toOwnedSlice();
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
