const std = @import("std");

pub const EventKind = enum {
    run_start,
    run_end,
    provider_request,
    provider_response,
    tool_request,
    tool_response,
    memory_recall,
    policy_decision,
    delegation_start,
    delegation_end,
};

pub const TraceEvent = struct {
    index: usize,
    kind: EventKind,
    ts_ms: i64,
    request_id: []const u8,
    turn: ?usize = null,
    payload_json: []u8,

    pub fn deinit(self: *TraceEvent, a: std.mem.Allocator) void {
        a.free(self.payload_json);
    }
};
