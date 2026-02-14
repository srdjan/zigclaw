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

    pub fn fromConfig(cfg: config.ValidatedConfig) Logger {
        return .{
            .enabled = cfg.raw.observability.enabled,
            .dir = cfg.raw.observability.dir,
            .max_file_bytes = cfg.raw.observability.max_file_bytes,
            .max_files = cfg.raw.observability.max_files,
            .workspace_root = cfg.raw.security.workspace_root,
        };
    }

    pub fn logJson(self: Logger, a: std.mem.Allocator, kind: EventKind, request_id: []const u8, payload_obj: anytype) void {
        if (!self.enabled) return;

        const line = buildEventLine(a, kind, request_id, payload_obj) catch |e| {
            std.log.err("obs: failed to build log line: {s}", .{@errorName(e)});
            return;
        };
        defer a.free(line);

        appendLineBestEffort(self, a, line);
    }
};

fn buildEventLine(a: std.mem.Allocator, kind: EventKind, request_id: []const u8, payload_obj: anytype) ![]u8 {
    var stream = std.json.StringifyStream.init(a);
    defer stream.deinit();

    const now_ms = std.time.milliTimestamp();

    try stream.beginObject();
    try stream.objectField("ts_ms"); try stream.write(now_ms);
    try stream.objectField("kind"); try stream.write(@tagName(kind));
    try stream.objectField("request_id"); try stream.write(request_id);
    try stream.objectField("payload"); try stream.write(payload_obj);
    try stream.endObject();

    // JSONL newline added by writer
    const json = try stream.toOwnedSlice();
    var out = try a.alloc(u8, json.len + 1);
    std.mem.copyForwards(u8, out[0..json.len], json);
    out[json.len] = '\n';
    a.free(json);
    return out;
}

fn appendLineBestEffort(self: Logger, a: std.mem.Allocator, line: []const u8) void {
    // Resolve log dir relative to workspace root for predictable behavior.
    const dir = std.fs.path.join(a, &.{ self.workspace_root, self.dir }) catch return;
    defer a.free(dir);

    std.fs.cwd().makePath(dir) catch |e| {
        std.log.err("obs: makePath failed: {s}", .{@errorName(e)});
        return;
    };

    rotateIfNeeded(self, a, dir) catch |e| {
        std.log.err("obs: rotate failed: {s}", .{@errorName(e)});
        // keep going and attempt append anyway
    };

    const path = std.fs.path.join(a, &.{ dir, "zigclaw.jsonl" }) catch return;
    defer a.free(path);

    var file = std.fs.cwd().openFile(path, .{ .mode = .read_write }) catch |e| {
        if (e == error.FileNotFound) {
            var f = std.fs.cwd().createFile(path, .{ .truncate = false }) catch |e2| {
                std.log.err("obs: create log file failed: {s}", .{@errorName(e2)});
                return;
            };
            defer f.close();
            f.seekFromEnd(0) catch {};
            f.writer().writeAll(line) catch {};
            return;
        }
        std.log.err("obs: open log file failed: {s}", .{@errorName(e)});
        return;
    };
    defer file.close();

    file.seekFromEnd(0) catch {};
    file.writer().writeAll(line) catch {};
}

fn rotateIfNeeded(self: Logger, a: std.mem.Allocator, dir: []const u8) !void {
    if (self.max_files == 0) return;

    const base = try std.fs.path.join(a, &.{ dir, "zigclaw.jsonl" });
    defer a.free(base);

    const st = std.fs.cwd().statFile(base) catch return;
    if (st.size < self.max_file_bytes) return;

    // delete oldest: zigclaw.jsonl.<max_files>
    const oldest = try std.fmt.allocPrint(a, "{s}.{d}", .{ base, self.max_files });
    defer a.free(oldest);
    _ = std.fs.cwd().deleteFile(oldest) catch {};

    // shift: N-1 -> N
    var i: u32 = self.max_files;
    while (i > 1) : (i -= 1) {
        const from = try std.fmt.allocPrint(a, "{s}.{d}", .{ base, i - 1 });
        defer a.free(from);
        const to = try std.fmt.allocPrint(a, "{s}.{d}", .{ base, i });
        defer a.free(to);
        std.fs.cwd().rename(from, to) catch {};
    }

    // base -> .1
    const to1 = try std.fmt.allocPrint(a, "{s}.1", .{ base });
    defer a.free(to1);
    std.fs.cwd().rename(base, to1) catch {};
}
