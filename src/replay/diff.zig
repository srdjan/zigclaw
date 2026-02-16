const std = @import("std");

pub fn diffCapsulesJsonAlloc(a: std.mem.Allocator, left_json: []const u8, right_json: []const u8) ![]u8 {
    var left = try std.json.parseFromSlice(std.json.Value, a, left_json, .{});
    defer left.deinit();
    var right = try std.json.parseFromSlice(std.json.Value, a, right_json, .{});
    defer right.deinit();
    if (left.value != .object or right.value != .object) return error.InvalidCapsule;

    const left_events = getEvents(left.value.object) orelse return error.InvalidCapsule;
    const right_events = getEvents(right.value.object) orelse return error.InvalidCapsule;

    const min_len = @min(left_events.len, right_events.len);
    var first_diff: ?usize = null;
    var i: usize = 0;
    while (i < min_len) : (i += 1) {
        if (!jsonValueEq(a, left_events[i], right_events[i])) {
            first_diff = i;
            break;
        }
    }
    if (first_diff == null and left_events.len != right_events.len) {
        first_diff = min_len;
    }

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("equal");
    try stream.write(first_diff == null);
    try stream.objectField("left_event_count");
    try stream.write(left_events.len);
    try stream.objectField("right_event_count");
    try stream.write(right_events.len);
    try stream.objectField("first_diff_index");
    try stream.write(first_diff);
    if (first_diff) |idx| {
        try stream.objectField("left_event");
        if (idx < left_events.len) {
            try stream.write(left_events[idx]);
        } else {
            try stream.write(null);
        }
        try stream.objectField("right_event");
        if (idx < right_events.len) {
            try stream.write(right_events[idx]);
        } else {
            try stream.write(null);
        }
    }
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn getEvents(obj: std.json.ObjectMap) ?[]const std.json.Value {
    const v = obj.get("events") orelse return null;
    if (v != .array) return null;
    return v.array.items;
}

fn jsonValueEq(a: std.mem.Allocator, lhs: std.json.Value, rhs: std.json.Value) bool {
    const l = stringifyAlloc(a, lhs) catch return false;
    defer a.free(l);
    const r = stringifyAlloc(a, rhs) catch return false;
    defer a.free(r);
    return std.mem.eql(u8, l, r);
}

fn stringifyAlloc(a: std.mem.Allocator, v: std.json.Value) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{
        .writer = &aw.writer,
        .options = .{ .whitespace = .minified },
    };
    try stream.write(v);
    return try aw.toOwnedSlice();
}
