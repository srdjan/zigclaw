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
        const url = try std.fmt.allocPrint(a, "{s}/chat/completions", .{std.mem.trimEnd(u8, self.base_url, "/")});
        defer a.free(url);

        const body = try buildRequestBody(a, req);
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

        return try parseChatCompletion(a, resp_bytes);
    }
};

fn buildRequestBody(a: std.mem.Allocator, req: provider.ChatRequest) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("model");
    try stream.write(req.model);
    try stream.objectField("temperature");
    try stream.write(req.temperature);

    try stream.objectField("messages");
    try stream.beginArray();

    if (req.messages.len > 0) {
        // Multi-turn path: use messages directly
        for (req.messages) |msg| {
            try writeMessage(&stream, &aw.writer, msg);
        }
    } else {
        // Legacy single-turn path: build from system/user/memory_context
        const sys = try buildSystemMessage(a, req.system, req.memory_context);
        defer a.free(sys);

        try stream.beginObject();
        try stream.objectField("role");
        try stream.write("system");
        try stream.objectField("content");
        try stream.write(sys);
        try stream.endObject();

        try stream.beginObject();
        try stream.objectField("role");
        try stream.write("user");
        try stream.objectField("content");
        try stream.write(req.user);
        try stream.endObject();
    }
    try stream.endArray();

    // Tool definitions
    if (req.tools.len > 0) {
        try stream.objectField("tools");
        try stream.beginArray();
        for (req.tools) |tool| {
            try stream.beginObject();
            try stream.objectField("type");
            try stream.write("function");
            try stream.objectField("function");
            try stream.beginObject();
            try stream.objectField("name");
            try stream.write(tool.name);
            try stream.objectField("description");
            try stream.write(tool.description);
            try stream.objectField("parameters");
            // parameters_json is already a JSON string; write raw
            try aw.writer.writeAll(tool.parameters_json);
            try stream.endObject(); // function
            try stream.endObject(); // tool
        }
        try stream.endArray();
    }

    try stream.objectField("stream");
    try stream.write(false);
    try stream.endObject();

    return try aw.toOwnedSlice();
}

fn writeMessage(stream: anytype, raw_writer: anytype, msg: provider.Message) !void {
    try stream.beginObject();
    try stream.objectField("role");
    try stream.write(@tagName(msg.role));

    if (msg.content) |c| {
        try stream.objectField("content");
        try stream.write(c);
    } else {
        try stream.objectField("content");
        // Write raw "null" to avoid string quoting
        try raw_writer.writeAll("null");
    }

    // Assistant messages with tool calls
    if (msg.tool_calls.len > 0) {
        try stream.objectField("tool_calls");
        try stream.beginArray();
        for (msg.tool_calls) |tc| {
            try stream.beginObject();
            try stream.objectField("id");
            try stream.write(tc.id);
            try stream.objectField("type");
            try stream.write("function");
            try stream.objectField("function");
            try stream.beginObject();
            try stream.objectField("name");
            try stream.write(tc.name);
            try stream.objectField("arguments");
            try stream.write(tc.arguments);
            try stream.endObject(); // function
            try stream.endObject(); // tool call
        }
        try stream.endArray();
    }

    // Tool result messages
    if (msg.tool_call_id) |id| {
        try stream.objectField("tool_call_id");
        try stream.write(id);
    }

    try stream.endObject();
}

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

pub fn parseChatCompletion(a: std.mem.Allocator, bytes: []const u8) !provider.ChatResponse {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ta = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, ta, bytes, .{}) catch return error.InvalidJson;
    const root = parsed.value;

    const choices = root.object.get("choices") orelse return error.InvalidResponse;
    if (choices != .array or choices.array.items.len == 0) return error.InvalidResponse;
    const first = choices.array.items[0];

    // Parse finish_reason
    const finish_reason: provider.FinishReason = blk: {
        const fr = first.object.get("finish_reason") orelse break :blk .unknown;
        if (fr != .string) break :blk .unknown;
        if (std.mem.eql(u8, fr.string, "stop")) break :blk .stop;
        if (std.mem.eql(u8, fr.string, "tool_calls")) break :blk .tool_calls;
        if (std.mem.eql(u8, fr.string, "length")) break :blk .length;
        break :blk .unknown;
    };

    const msg = first.object.get("message") orelse return error.InvalidResponse;

    // Parse content (may be null when tool_calls are present)
    const content: []u8 = blk: {
        const content_v = msg.object.get("content") orelse break :blk try a.dupe(u8, "");
        if (content_v == .string) break :blk try a.dupe(u8, content_v.string);
        break :blk try a.dupe(u8, "");
    };

    // Parse tool_calls
    var tool_calls: []provider.ToolCall = &.{};
    if (msg.object.get("tool_calls")) |tc_val| {
        if (tc_val == .array and tc_val.array.items.len > 0) {
            var tcs = std.array_list.Managed(provider.ToolCall).init(a);
            for (tc_val.array.items) |tc_item| {
                if (tc_item != .object) continue;
                const id = if (tc_item.object.get("id")) |v| switch (v) {
                    .string => |s| s,
                    else => "",
                } else "";
                const func = tc_item.object.get("function") orelse continue;
                if (func != .object) continue;
                const name = if (func.object.get("name")) |v| switch (v) {
                    .string => |s| s,
                    else => continue,
                } else continue;
                const arguments = if (func.object.get("arguments")) |v| switch (v) {
                    .string => |s| s,
                    else => "{}",
                } else "{}";

                try tcs.append(.{
                    .id = try a.dupe(u8, id),
                    .name = try a.dupe(u8, name),
                    .arguments = try a.dupe(u8, arguments),
                });
            }
            tool_calls = try tcs.toOwnedSlice();
        }
    }

    // Parse usage (prompt_tokens, completion_tokens, total_tokens)
    var usage: provider.TokenUsage = .{};
    if (root.object.get("usage")) |usage_val| {
        if (usage_val == .object) {
            if (usage_val.object.get("prompt_tokens")) |v| {
                if (v == .integer) usage.prompt_tokens = std.math.cast(u64, v.integer) orelse 0;
            }
            if (usage_val.object.get("completion_tokens")) |v| {
                if (v == .integer) usage.completion_tokens = std.math.cast(u64, v.integer) orelse 0;
            }
            if (usage_val.object.get("total_tokens")) |v| {
                if (v == .integer) usage.total_tokens = std.math.cast(u64, v.integer) orelse 0;
            }
        }
    }

    return .{
        .content = content,
        .tool_calls = tool_calls,
        .finish_reason = finish_reason,
        .usage = usage,
    };
}
