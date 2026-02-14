const std = @import("std");

pub const DecisionEvent = struct {
    ts_unix_ms: i64,
    decision: []const u8,
    subject: []const u8,
    allowed: bool,
    reason: []const u8,
    policy_hash: []const u8,
};

pub fn logDecision(a: std.mem.Allocator, ev: DecisionEvent) !void {
    // Default log path; configurable later.
    const dir = ".zigclaw";
    const path = ".zigclaw/decisions.jsonl";

    try std.fs.cwd().makePath(dir);

    var file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();

    // append
    try file.seekFromEnd(0);

    var stream = std.json.StringifyStream.init(a);
    defer stream.deinit();

    try stream.beginObject();
    try stream.objectField("ts_unix_ms"); try stream.write(ev.ts_unix_ms);
    try stream.objectField("decision"); try stream.write(ev.decision);
    try stream.objectField("subject"); try stream.write(ev.subject);
    try stream.objectField("allowed"); try stream.write(ev.allowed);
    try stream.objectField("reason"); try stream.write(ev.reason);
    try stream.objectField("policy_hash"); try stream.write(ev.policy_hash);
    try stream.endObject();

    const line = try stream.toOwnedSlice();
    defer a.free(line);

    try file.writer().writeAll(line);
    try file.writer().writeAll("\n");
}

pub fn nowUnixMs() i64 {
    // best-effort; not monotonic
    const ns = std.time.nanoTimestamp();
    return @as(i64, @intCast(@divTrunc(ns, 1_000_000)));
}
