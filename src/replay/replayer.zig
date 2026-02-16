const std = @import("std");

pub const CapsuleRunSeed = struct {
    request_id: []u8,
    message: []u8,

    pub fn deinit(self: *CapsuleRunSeed, a: std.mem.Allocator) void {
        a.free(self.request_id);
        a.free(self.message);
    }
};

pub fn extractRunSeedAlloc(a: std.mem.Allocator, capsule_json: []const u8) !CapsuleRunSeed {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, capsule_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidCapsule;

    const obj = parsed.value.object;
    const request_id = getString(obj, "request_id") orelse return error.InvalidCapsule;
    const events_v = obj.get("events") orelse return error.InvalidCapsule;
    if (events_v != .array) return error.InvalidCapsule;

    var message: []const u8 = "";
    for (events_v.array.items) |ev| {
        if (ev != .object) continue;
        const ev_obj = ev.object;
        const kind = getString(ev_obj, "kind") orelse continue;
        if (!std.mem.eql(u8, kind, "run_start")) continue;

        const payload_v = ev_obj.get("payload") orelse continue;
        if (payload_v != .object) continue;
        const payload_obj = payload_v.object;
        const m = getString(payload_obj, "message") orelse continue;
        message = m;
        break;
    }

    return .{
        .request_id = try a.dupe(u8, request_id),
        .message = try a.dupe(u8, message),
    };
}

pub fn replayFromCapsuleJsonAlloc(a: std.mem.Allocator, capsule_json: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, capsule_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidCapsule;

    const obj = parsed.value.object;
    const request_id = getString(obj, "request_id") orelse return error.InvalidCapsule;
    const events_v = obj.get("events") orelse return error.InvalidCapsule;
    if (events_v != .array) return error.InvalidCapsule;

    var content: []const u8 = "";
    var turns: usize = 0;
    var found = false;

    for (events_v.array.items) |ev| {
        if (ev != .object) continue;
        const ev_obj = ev.object;
        const kind = getString(ev_obj, "kind") orelse continue;
        if (!std.mem.eql(u8, kind, "run_end")) continue;
        const payload_v = ev_obj.get("payload") orelse continue;
        if (payload_v != .object) continue;
        const payload = payload_v.object;
        const content_v = payload.get("content") orelse continue;
        const turns_v = payload.get("turns") orelse continue;
        if (content_v != .string) continue;
        if (turns_v != .integer or turns_v.integer < 0) continue;
        content = content_v.string;
        turns = @as(usize, @intCast(turns_v.integer));
        found = true;
    }
    if (!found) return error.RunEndNotFound;

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("content");
    try stream.write(content);
    try stream.objectField("turns");
    try stream.write(turns);
    try stream.objectField("replayed");
    try stream.write(true);
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn getString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    if (v != .string) return null;
    return v.string;
}
