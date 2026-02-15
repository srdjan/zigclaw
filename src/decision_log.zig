const std = @import("std");

pub const DecisionEvent = struct {
    ts_unix_ms: i64,
    decision: []const u8,
    subject: []const u8,
    allowed: bool,
    reason: []const u8,
    policy_hash: []const u8,
};

pub fn logDecision(a: std.mem.Allocator, io: std.Io, ev: DecisionEvent) !void {
    // Default log path; configurable later.
    const dir = ".zigclaw";
    const path = ".zigclaw/decisions.jsonl";

    try std.Io.Dir.cwd().createDirPath(io, dir);

    var out = std.Io.Writer.Allocating.init(a);
    var stream: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .whitespace = .minified },
    };

    try stream.beginObject();
    try stream.objectField("ts_unix_ms");
    try stream.write(ev.ts_unix_ms);
    try stream.objectField("decision");
    try stream.write(ev.decision);
    try stream.objectField("subject");
    try stream.write(ev.subject);
    try stream.objectField("allowed");
    try stream.write(ev.allowed);
    try stream.objectField("reason");
    try stream.write(ev.reason);
    try stream.objectField("policy_hash");
    try stream.write(ev.policy_hash);
    try stream.endObject();

    const json = try out.toOwnedSlice();
    defer a.free(json);

    // Build line with trailing newline
    var line = try a.alloc(u8, json.len + 1);
    defer a.free(line);
    @memcpy(line[0..json.len], json);
    line[json.len] = '\n';

    // O(1) append: open/create file without truncating, write at the current end.
    var f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false });
    defer f.close(io);

    const st = std.Io.Dir.cwd().statFile(io, path, .{}) catch return;
    try f.writePositionalAll(io, line, st.size);
}

pub fn nowUnixMs(io: std.Io) i64 {
    const ts = std.Io.Clock.now(.real, io);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}
