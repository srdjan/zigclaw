const std = @import("std");
const config = @import("../config.zig");
const workspace_mod = @import("../agent/workspace.zig");
const att_receipt = @import("../attestation/receipt.zig");
const event_mod = @import("event.zig");
const capsule_mod = @import("capsule.zig");

pub const TraceRecorder = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    enabled: bool,
    workspace_root: []const u8,
    request_id: []const u8,
    next_index: usize = 0,
    events: std.array_list.Managed(event_mod.TraceEvent),

    pub fn init(
        a: std.mem.Allocator,
        io: std.Io,
        workspace_root: []const u8,
        request_id: []const u8,
        enabled: bool,
    ) TraceRecorder {
        return .{
            .allocator = a,
            .io = io,
            .enabled = enabled,
            .workspace_root = workspace_root,
            .request_id = request_id,
            .next_index = 0,
            .events = std.array_list.Managed(event_mod.TraceEvent).init(a),
        };
    }

    pub fn deinit(self: *TraceRecorder) void {
        for (self.events.items) |*ev| ev.deinit(self.allocator);
        self.events.deinit();
    }

    pub fn record(self: *TraceRecorder, kind: event_mod.EventKind, turn: ?usize, payload_obj: anytype) !void {
        if (!self.enabled) return;

        var payload_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer payload_buf.deinit();
        var payload_stream: std.json.Stringify = .{
            .writer = &payload_buf.writer,
            .options = .{ .whitespace = .minified },
        };
        try payload_stream.write(payload_obj);

        try self.events.append(.{
            .index = self.next_index,
            .kind = kind,
            .ts_ms = nowMs(self.io),
            .request_id = self.request_id,
            .turn = turn,
            .payload_json = try payload_buf.toOwnedSlice(),
        });
        self.next_index += 1;
    }

    pub fn finalize(
        self: *TraceRecorder,
        cfg: config.ValidatedConfig,
        policy_hash: []const u8,
        prompt_hash: ?[]const u8,
    ) !void {
        if (!self.enabled) return;

        const path = try capsule_mod.capsulePathAlloc(self.allocator, self.workspace_root, self.request_id);
        defer self.allocator.free(path);

        const dir = try std.fs.path.join(self.allocator, &.{ self.workspace_root, ".zigclaw", "capsules" });
        defer self.allocator.free(dir);
        try std.Io.Dir.cwd().createDirPath(self.io, dir);

        var normalized_cfg: std.Io.Writer.Allocating = .init(self.allocator);
        defer normalized_cfg.deinit();
        try cfg.printNormalizedToml(self.allocator, &normalized_cfg.writer);
        const cfg_text = try normalized_cfg.toOwnedSlice();
        defer self.allocator.free(cfg_text);

        var snapshot = workspace_mod.scan(self.allocator, self.io, self.workspace_root, .{}) catch blk: {
            break :blk workspace_mod.WorkspaceSnapshot{
                .root = try self.allocator.dupe(u8, self.workspace_root),
                .files = try self.allocator.alloc(workspace_mod.FileEntry, 0),
                .skipped_large_files = 0,
            };
        };
        defer snapshot.deinit(self.allocator);

        const receipt_json = att_receipt.readReceiptJsonAlloc(
            self.allocator,
            self.io,
            self.workspace_root,
            self.request_id,
        ) catch null;
        defer if (receipt_json) |r| self.allocator.free(r);

        const capsule_json = try self.toCapsuleJsonAlloc(cfg_text, snapshot, policy_hash, prompt_hash, receipt_json);
        defer self.allocator.free(capsule_json);

        var f = try std.Io.Dir.cwd().createFile(self.io, path, .{ .truncate = true });
        defer f.close(self.io);
        var fbuf: [4096]u8 = undefined;
        var fw = f.writer(self.io, &fbuf);
        try fw.interface.writeAll(capsule_json);
        try fw.interface.writeAll("\n");
        try fw.flush();
    }

    fn toCapsuleJsonAlloc(
        self: *TraceRecorder,
        cfg_text: []const u8,
        snapshot: workspace_mod.WorkspaceSnapshot,
        policy_hash: []const u8,
        prompt_hash: ?[]const u8,
        receipt_json: ?[]const u8,
    ) ![]u8 {
        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        var stream: std.json.Stringify = .{ .writer = &aw.writer };

        try stream.beginObject();
        try stream.objectField("request_id");
        try stream.write(self.request_id);
        try stream.objectField("policy_hash");
        try stream.write(policy_hash);
        try stream.objectField("prompt_hash");
        try stream.write(prompt_hash);
        try stream.objectField("config_normalized");
        try stream.write(cfg_text);

        try stream.objectField("workspace_snapshot");
        try stream.beginObject();
        try stream.objectField("root");
        try stream.write(snapshot.root);
        try stream.objectField("skipped_large_files");
        try stream.write(snapshot.skipped_large_files);
        try stream.objectField("files");
        try stream.beginArray();
        for (snapshot.files) |f| {
            try stream.beginObject();
            try stream.objectField("rel_path");
            try stream.write(f.rel_path);
            try stream.objectField("size");
            try stream.write(f.size);
            try stream.objectField("sha256_hex");
            try stream.write(f.sha256_hex);
            try stream.endObject();
        }
        try stream.endArray();
        try stream.endObject();

        try stream.objectField("events");
        try stream.beginArray();
        for (self.events.items) |ev| {
            try stream.beginObject();
            try stream.objectField("index");
            try stream.write(ev.index);
            try stream.objectField("kind");
            try stream.write(@tagName(ev.kind));
            try stream.objectField("ts_ms");
            try stream.write(ev.ts_ms);
            try stream.objectField("request_id");
            try stream.write(ev.request_id);
            try stream.objectField("turn");
            try stream.write(ev.turn);
            try stream.objectField("payload");
            try writeJsonStringValue(&stream, self.allocator, ev.payload_json);
            try stream.endObject();
        }
        try stream.endArray();

        try stream.objectField("receipt");
        if (receipt_json) |rj| {
            try writeJsonStringValue(&stream, self.allocator, rj);
        } else {
            try stream.write(null);
        }
        try stream.endObject();

        return try aw.toOwnedSlice();
    }
};

fn writeJsonStringValue(stream: *std.json.Stringify, a: std.mem.Allocator, json_text: []const u8) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, a, json_text, .{}) catch {
        try stream.write(json_text);
        return;
    };
    defer parsed.deinit();
    try stream.write(parsed.value);
}

fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Clock.now(.real, io);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}
