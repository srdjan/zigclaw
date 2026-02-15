const std = @import("std");
const config = @import("config.zig");

pub const DecisionEvent = struct {
    ts_unix_ms: i64,
    request_id: []const u8,
    prompt_hash: ?[]const u8 = null,
    decision: []const u8,
    subject: []const u8,
    allowed: bool,
    reason: []const u8,
    policy_hash: []const u8,
};

pub const Logger = struct {
    enabled: bool,
    dir: []const u8,
    file: []const u8,
    max_file_bytes: u64,
    max_files: u32,
    workspace_root: []const u8,
    io: std.Io,

    pub fn fromConfig(cfg: config.ValidatedConfig, io: std.Io) Logger {
        return .{
            .enabled = cfg.raw.logging.enabled,
            .dir = cfg.raw.logging.dir,
            .file = cfg.raw.logging.file,
            .max_file_bytes = cfg.raw.logging.max_file_bytes,
            .max_files = cfg.raw.logging.max_files,
            .workspace_root = cfg.raw.security.workspace_root,
            .io = io,
        };
    }

    pub fn log(self: Logger, a: std.mem.Allocator, ev: DecisionEvent) void {
        if (!self.enabled) return;

        const line = buildEventLine(a, ev) catch |e| {
            std.log.err("decision_log: failed to build log line: {s}", .{@errorName(e)});
            return;
        };
        defer a.free(line);

        appendLineBestEffort(self, a, line);
    }
};

pub fn logDecision(a: std.mem.Allocator, io: std.Io, ev: DecisionEvent) !void {
    const d = config.LoggingConfig{};
    const l = Logger{
        .enabled = d.enabled,
        .dir = d.dir,
        .file = d.file,
        .max_file_bytes = d.max_file_bytes,
        .max_files = d.max_files,
        .workspace_root = ".",
        .io = io,
    };

    const line = try buildEventLine(a, ev);
    defer a.free(line);
    try appendLine(l, a, line);
}

fn buildEventLine(a: std.mem.Allocator, ev: DecisionEvent) ![]u8 {
    var out = std.Io.Writer.Allocating.init(a);
    var stream: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .whitespace = .minified },
    };

    try stream.beginObject();
    try stream.objectField("ts_unix_ms");
    try stream.write(ev.ts_unix_ms);
    try stream.objectField("request_id");
    try stream.write(ev.request_id);
    try stream.objectField("prompt_hash");
    try stream.write(ev.prompt_hash);
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
    @memcpy(line[0..json.len], json);
    line[json.len] = '\n';
    return line;
}

fn appendLineBestEffort(self: Logger, a: std.mem.Allocator, line: []const u8) void {
    appendLine(self, a, line) catch |e| {
        std.log.err("decision_log: append failed: {s}", .{@errorName(e)});
    };
}

fn appendLine(self: Logger, a: std.mem.Allocator, line: []const u8) !void {
    const dir = if (std.fs.path.isAbsolute(self.dir))
        try a.dupe(u8, self.dir)
    else
        try std.fs.path.join(a, &.{ self.workspace_root, self.dir });
    defer a.free(dir);

    try std.Io.Dir.cwd().createDirPath(self.io, dir);
    try rotateIfNeeded(self, a, dir);

    const path = try std.fs.path.join(a, &.{ dir, self.file });
    defer a.free(path);

    var f = try std.Io.Dir.cwd().createFile(self.io, path, .{ .truncate = false });
    defer f.close(self.io);

    const st = std.Io.Dir.cwd().statFile(self.io, path, .{}) catch return;
    try f.writePositionalAll(self.io, line, st.size);
}

fn rotateIfNeeded(self: Logger, a: std.mem.Allocator, dir: []const u8) !void {
    if (self.max_files == 0) return;

    const base = try std.fs.path.join(a, &.{ dir, self.file });
    defer a.free(base);

    const st = std.Io.Dir.cwd().statFile(self.io, base, .{}) catch return;
    if (st.size < self.max_file_bytes) return;

    const oldest = try std.fmt.allocPrint(a, "{s}.{d}", .{ base, self.max_files });
    defer a.free(oldest);
    _ = std.Io.Dir.cwd().deleteFile(self.io, oldest) catch {};

    var i: u32 = self.max_files;
    while (i > 1) : (i -= 1) {
        const from = try std.fmt.allocPrint(a, "{s}.{d}", .{ base, i - 1 });
        defer a.free(from);
        const to = try std.fmt.allocPrint(a, "{s}.{d}", .{ base, i });
        defer a.free(to);
        std.Io.Dir.rename(std.Io.Dir.cwd(), from, std.Io.Dir.cwd(), to, self.io) catch {};
    }

    const to1 = try std.fmt.allocPrint(a, "{s}.1", .{base});
    defer a.free(to1);
    std.Io.Dir.rename(std.Io.Dir.cwd(), base, std.Io.Dir.cwd(), to1, self.io) catch {};
}

pub fn nowUnixMs(io: std.Io) i64 {
    const ts = std.Io.Clock.now(.real, io);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}
