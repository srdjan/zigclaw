const std = @import("std");

pub const DecisionEvent = struct {
    ts_unix_ms: i64,
    request_id: []const u8,
    prompt_hash: ?[]const u8,
    decision: []const u8,
    subject: []const u8,
    allowed: bool,
    reason: []const u8,
    policy_hash: []const u8,

    pub fn deinit(self: *DecisionEvent, a: std.mem.Allocator) void {
        a.free(self.request_id);
        if (self.prompt_hash) |ph| a.free(ph);
        a.free(self.decision);
        a.free(self.subject);
        a.free(self.reason);
        a.free(self.policy_hash);
    }
};

pub const ReadOpts = struct {
    from_ts: ?i64 = null,
    to_ts: ?i64 = null,
    request_id: ?[]const u8 = null,
};

pub fn readEvents(a: std.mem.Allocator, io: std.Io, dir: []const u8, file: []const u8, opts: ReadOpts) ![]DecisionEvent {
    var events = std.array_list.Managed(DecisionEvent).init(a);
    errdefer {
        for (events.items) |*ev| ev.deinit(a);
        events.deinit();
    }

    // Read rotated files first (oldest first): .5, .4, .3, .2, .1, then base
    var i: u32 = 5;
    while (i >= 1) : (i -= 1) {
        const rotated_name = try std.fmt.allocPrint(a, "{s}.{d}", .{ file, i });
        defer a.free(rotated_name);
        const rotated_path = try std.fs.path.join(a, &.{ dir, rotated_name });
        defer a.free(rotated_path);
        try readEventsFromFile(a, io, rotated_path, opts, &events);
    }

    // Read base file
    const base_path = try std.fs.path.join(a, &.{ dir, file });
    defer a.free(base_path);
    try readEventsFromFile(a, io, base_path, opts, &events);

    return try events.toOwnedSlice();
}

fn readEventsFromFile(
    a: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    opts: ReadOpts,
    events: *std.array_list.Managed(DecisionEvent),
) !void {
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(16 * 1024 * 1024)) catch return;
    defer a.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;

        const ev = parseEvent(a, trimmed) catch continue;
        errdefer {
            var ev_mut = ev;
            ev_mut.deinit(a);
        }

        // Apply filters
        if (opts.from_ts) |from| {
            if (ev.ts_unix_ms < from) {
                var ev_mut = ev;
                ev_mut.deinit(a);
                continue;
            }
        }
        if (opts.to_ts) |to| {
            if (ev.ts_unix_ms > to) {
                var ev_mut = ev;
                ev_mut.deinit(a);
                continue;
            }
        }
        if (opts.request_id) |rid| {
            if (!std.mem.eql(u8, ev.request_id, rid)) {
                var ev_mut = ev;
                ev_mut.deinit(a);
                continue;
            }
        }

        try events.append(ev);
    }
}

fn parseEvent(a: std.mem.Allocator, json: []const u8) !DecisionEvent {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidEvent;
    const obj = parsed.value.object;

    return .{
        .ts_unix_ms = blk: {
            const v = obj.get("ts_unix_ms") orelse return error.InvalidEvent;
            break :blk switch (v) {
                .integer => |i| i,
                else => return error.InvalidEvent,
            };
        },
        .request_id = try dupeStr(a, obj, "request_id"),
        .prompt_hash = dupeStr(a, obj, "prompt_hash") catch null,
        .decision = try dupeStr(a, obj, "decision"),
        .subject = try dupeStr(a, obj, "subject"),
        .allowed = blk: {
            const v = obj.get("allowed") orelse return error.InvalidEvent;
            break :blk switch (v) {
                .bool => |b| b,
                else => return error.InvalidEvent,
            };
        },
        .reason = try dupeStr(a, obj, "reason"),
        .policy_hash = try dupeStr(a, obj, "policy_hash"),
    };
}

fn dupeStr(a: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const v = obj.get(key) orelse return error.InvalidEvent;
    return switch (v) {
        .string => |s| try a.dupe(u8, s),
        .null => error.InvalidEvent,
        else => error.InvalidEvent,
    };
}

pub fn freeEvents(a: std.mem.Allocator, events: []DecisionEvent) void {
    for (events) |*ev| {
        var e = ev.*;
        e.deinit(a);
    }
    a.free(events);
}
