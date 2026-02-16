const std = @import("std");
const provider = @import("provider.zig");

const ReplayState = struct {
    capsule_path: []u8,
    capsule_bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),
    next_provider_index: usize = 0,
    next_tool_index: usize = 0,
};

pub const CapsuleReplayProvider = struct {
    state: *ReplayState,

    pub fn init(a: std.mem.Allocator, io: std.Io, capsule_path: []const u8) !CapsuleReplayProvider {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, capsule_path, a, std.Io.Limit.limited(8 * 1024 * 1024));
        errdefer a.free(bytes);

        const parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
        errdefer {
            var p = parsed;
            p.deinit();
        }

        // Validate core capsule shape at load-time.
        if (parsed.value != .object) return error.InvalidCapsule;
        const obj = parsed.value.object;
        const request_id_v = obj.get("request_id") orelse return error.InvalidCapsule;
        if (request_id_v != .string) return error.InvalidCapsule;
        const events_v = obj.get("events") orelse return error.InvalidCapsule;
        if (events_v != .array) return error.InvalidCapsule;

        const state = try a.create(ReplayState);
        state.* = .{
            .capsule_path = try a.dupe(u8, capsule_path),
            .capsule_bytes = bytes,
            .parsed = parsed,
            .next_provider_index = 0,
            .next_tool_index = 0,
        };

        return .{ .state = state };
    }

    pub fn deinit(self: *CapsuleReplayProvider, a: std.mem.Allocator) void {
        a.free(self.state.capsule_path);
        self.state.parsed.deinit();
        a.free(self.state.capsule_bytes);
        a.destroy(self.state);
    }

    pub fn chat(self: CapsuleReplayProvider, a: std.mem.Allocator, _: std.Io, _: provider.ChatRequest) !provider.ChatResponse {
        const events = getEvents(self.state.parsed.value.object) orelse return error.InvalidCapsule;

        var i = self.state.next_provider_index;
        while (i < events.len) : (i += 1) {
            const kind = eventKind(events[i]) orelse continue;
            if (!std.mem.eql(u8, kind, "provider_response")) continue;

            const payload = eventPayload(events[i]) orelse return error.InvalidCapsule;
            const turn = eventTurn(events[i]);

            const finish_reason = finishReasonFromString(getString(payload, "finish_reason") orelse "stop");
            const content = getString(payload, "content") orelse "";
            const usage = parseUsage(payload);
            const tool_calls = try collectToolCallsForTurn(a, events, i + 1, turn);

            self.state.next_provider_index = i + 1;
            if (self.state.next_tool_index < i + 1) self.state.next_tool_index = i + 1;

            return .{
                .content = try a.dupe(u8, content),
                .tool_calls = tool_calls,
                .finish_reason = finish_reason,
                .usage = usage,
            };
        }

        return error.CapsuleReplayExhausted;
    }

    pub fn replayToolResult(self: CapsuleReplayProvider, a: std.mem.Allocator, tool_call_id: []const u8) !?provider.ReplayedToolResult {
        const events = getEvents(self.state.parsed.value.object) orelse return error.InvalidCapsule;

        var i = self.state.next_tool_index;
        while (i < events.len) : (i += 1) {
            const kind = eventKind(events[i]) orelse continue;
            if (!std.mem.eql(u8, kind, "tool_response")) continue;

            const payload = eventPayload(events[i]) orelse return error.InvalidCapsule;
            const this_id = getString(payload, "tool_call_id") orelse continue;
            if (!std.mem.eql(u8, this_id, tool_call_id)) continue;

            const ok = getBool(payload, "ok") orelse false;
            const content = if (getString(payload, "content")) |c|
                try a.dupe(u8, c)
            else if (getString(payload, "error")) |e|
                try std.fmt.allocPrint(a, "Tool execution error: {s}", .{e})
            else
                try a.dupe(u8, "");

            self.state.next_tool_index = i + 1;
            return .{ .ok = ok, .content = content };
        }

        return error.CapsuleToolReplayNotFound;
    }
};

fn getEvents(obj: std.json.ObjectMap) ?[]const std.json.Value {
    const events_v = obj.get("events") orelse return null;
    if (events_v != .array) return null;
    return events_v.array.items;
}

fn eventKind(ev: std.json.Value) ?[]const u8 {
    if (ev != .object) return null;
    return getString(ev.object, "kind");
}

fn eventPayload(ev: std.json.Value) ?std.json.ObjectMap {
    if (ev != .object) return null;
    const payload_v = ev.object.get("payload") orelse return null;
    if (payload_v != .object) return null;
    return payload_v.object;
}

fn eventTurn(ev: std.json.Value) ?usize {
    if (ev != .object) return null;
    const turn_v = ev.object.get("turn") orelse return null;
    if (turn_v == .null) return null;
    if (turn_v != .integer or turn_v.integer < 0) return null;
    return @as(usize, @intCast(turn_v.integer));
}

fn collectToolCallsForTurn(
    a: std.mem.Allocator,
    events: []const std.json.Value,
    start_idx: usize,
    turn: ?usize,
) ![]provider.ToolCall {
    var out = std.array_list.Managed(provider.ToolCall).init(a);
    errdefer {
        for (out.items) |tc| {
            a.free(tc.id);
            a.free(tc.name);
            a.free(tc.arguments);
        }
        out.deinit();
    }

    var i = start_idx;
    while (i < events.len) : (i += 1) {
        const kind = eventKind(events[i]) orelse continue;
        if (std.mem.eql(u8, kind, "provider_request") or std.mem.eql(u8, kind, "provider_response") or std.mem.eql(u8, kind, "run_end")) break;
        if (!std.mem.eql(u8, kind, "tool_request")) continue;

        const event_turn = eventTurn(events[i]);
        if (turn) |t| {
            if (event_turn) |et| {
                if (et != t) continue;
            }
        }

        const payload = eventPayload(events[i]) orelse return error.InvalidCapsule;
        const name = getString(payload, "tool") orelse return error.InvalidCapsule;
        const id = getString(payload, "tool_call_id") orelse return error.InvalidCapsule;
        const args = getString(payload, "arguments") orelse "{}";

        try out.append(.{
            .id = try a.dupe(u8, id),
            .name = try a.dupe(u8, name),
            .arguments = try a.dupe(u8, args),
        });
    }

    return try out.toOwnedSlice();
}

fn parseUsage(payload: std.json.ObjectMap) provider.TokenUsage {
    const usage_v = payload.get("usage") orelse return .{};
    if (usage_v != .object) return .{};
    return .{
        .prompt_tokens = getU64(usage_v.object, "prompt_tokens") orelse 0,
        .completion_tokens = getU64(usage_v.object, "completion_tokens") orelse 0,
        .total_tokens = getU64(usage_v.object, "total_tokens") orelse 0,
    };
}

fn finishReasonFromString(s: []const u8) provider.FinishReason {
    if (std.mem.eql(u8, s, "stop")) return .stop;
    if (std.mem.eql(u8, s, "tool_calls")) return .tool_calls;
    if (std.mem.eql(u8, s, "length")) return .length;
    return .unknown;
}

fn getString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    if (v != .string) return null;
    return v.string;
}

fn getBool(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const v = obj.get(key) orelse return null;
    if (v != .bool) return null;
    return v.bool;
}

fn getU64(obj: std.json.ObjectMap, key: []const u8) ?u64 {
    const v = obj.get(key) orelse return null;
    if (v != .integer or v.integer < 0) return null;
    return @as(u64, @intCast(v.integer));
}
