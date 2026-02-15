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

    const line = try out.toOwnedSlice();
    defer a.free(line);

    // Read existing content, append new line, write back.
    const existing = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        a,
        std.Io.Limit.limited(4 * 1024 * 1024),
    ) catch "";
    defer if (existing.len > 0) a.free(existing);

    // Build combined: existing + line + newline
    var combined = try a.alloc(u8, existing.len + line.len + 1);
    defer a.free(combined);
    @memcpy(combined[0..existing.len], existing);
    @memcpy(combined[existing.len..][0..line.len], line);
    combined[existing.len + line.len] = '\n';

    var f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer f.close(io);

    var fbuf: [4096]u8 = undefined;
    var fw = f.writer(io, &fbuf);
    try fw.interface.writeAll(combined);
    try fw.flush();
}

pub fn nowUnixMs(io: std.Io) i64 {
    const ts = std.Io.Clock.now(.real, io);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}
