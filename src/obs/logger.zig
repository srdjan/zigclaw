const std = @import("std");
const config = @import("../config.zig");

pub const EventKind = enum {
    gateway_request,
    tool_run,
    agent_run,
    provider_call,
    err,
};

pub const Logger = struct {
    enabled: bool,
    dir: []const u8,
    max_file_bytes: u64,
    max_files: u32,
    workspace_root: []const u8,
    io: std.Io,

    pub fn fromConfig(cfg: config.ValidatedConfig, io: std.Io) Logger {
        return .{
            .enabled = cfg.raw.observability.enabled,
            .dir = cfg.raw.observability.dir,
            .max_file_bytes = cfg.raw.observability.max_file_bytes,
            .max_files = cfg.raw.observability.max_files,
            .workspace_root = cfg.raw.security.workspace_root,
            .io = io,
        };
    }

    pub fn logJson(self: Logger, a: std.mem.Allocator, kind: EventKind, request_id: []const u8, payload_obj: anytype) void {
        if (!self.enabled) return;

        const line = buildEventLine(self.io, a, kind, request_id, payload_obj) catch |e| {
            std.log.err("obs: failed to build log line: {s}", .{@errorName(e)});
            return;
        };
        defer a.free(line);

        appendLineBestEffort(self, a, line);
    }
};

fn buildEventLine(io: std.Io, a: std.mem.Allocator, kind: EventKind, request_id: []const u8, payload_obj: anytype) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    var stream: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .whitespace = .minified },
    };

    const ts = std.Io.Clock.now(.real, io);
    const now_ms: i64 = @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));

    try stream.beginObject();
    try stream.objectField("ts_ms");
    try stream.write(now_ms);
    try stream.objectField("kind");
    try stream.write(@tagName(kind));
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("payload");
    try stream.write(payload_obj);
    try stream.endObject();

    const json = try out.toOwnedSlice();
    var result = try a.alloc(u8, json.len + 1);
    @memcpy(result[0..json.len], json);
    result[json.len] = '\n';
    a.free(json);
    return result;
}

fn appendLineBestEffort(self: Logger, a: std.mem.Allocator, line: []const u8) void {
    const io = self.io;

    // Resolve log dir relative to workspace root for predictable behavior.
    const dir = std.fs.path.join(a, &.{ self.workspace_root, self.dir }) catch return;
    defer a.free(dir);

    std.Io.Dir.cwd().createDirPath(io, dir) catch |e| {
        std.log.err("obs: createDirPath failed: {s}", .{@errorName(e)});
        return;
    };

    rotateIfNeeded(self, a, dir) catch |e| {
        std.log.err("obs: rotate failed: {s}", .{@errorName(e)});
        // keep going and attempt append anyway
    };

    const path = std.fs.path.join(a, &.{ dir, "zigclaw.jsonl" }) catch return;
    defer a.free(path);

    // O(1) append: open/create file without truncating, write at the current end offset.
    // This avoids reading the entire file into memory and is crash-safe (worst case:
    // incomplete last line, not full data loss).
    var f = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false }) catch |e2| {
        std.log.err("obs: create log file failed: {s}", .{@errorName(e2)});
        return;
    };
    defer f.close(io);

    // Get current file size to write at the end
    const st = std.Io.Dir.cwd().statFile(io, path, .{}) catch return;
    f.writePositionalAll(io, line, st.size) catch {};
}

fn rotateIfNeeded(self: Logger, a: std.mem.Allocator, dir: []const u8) !void {
    if (self.max_files == 0) return;
    const io = self.io;

    const base = try std.fs.path.join(a, &.{ dir, "zigclaw.jsonl" });
    defer a.free(base);

    const st = std.Io.Dir.cwd().statFile(io, base, .{}) catch return;
    if (st.size < self.max_file_bytes) return;

    // delete oldest: zigclaw.jsonl.<max_files>
    const oldest = try std.fmt.allocPrint(a, "{s}.{d}", .{ base, self.max_files });
    defer a.free(oldest);
    _ = std.Io.Dir.cwd().deleteFile(io, oldest) catch {};

    // shift: N-1 -> N
    var i: u32 = self.max_files;
    while (i > 1) : (i -= 1) {
        const from = try std.fmt.allocPrint(a, "{s}.{d}", .{ base, i - 1 });
        defer a.free(from);
        const to = try std.fmt.allocPrint(a, "{s}.{d}", .{ base, i });
        defer a.free(to);
        std.Io.Dir.rename(std.Io.Dir.cwd(), from, std.Io.Dir.cwd(), to, io) catch {};
    }

    // base -> .1
    const to1 = try std.fmt.allocPrint(a, "{s}.1", .{base});
    defer a.free(to1);
    std.Io.Dir.rename(std.Io.Dir.cwd(), base, std.Io.Dir.cwd(), to1, io) catch {};
}
