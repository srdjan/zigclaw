const std = @import("std");

const EventKey = struct {
    kind: []const u8,
    turn: ?i64,
};

pub fn diffCapsulesJsonAlloc(a: std.mem.Allocator, left_json: []const u8, right_json: []const u8) ![]u8 {
    var left = try std.json.parseFromSlice(std.json.Value, a, left_json, .{});
    defer left.deinit();
    var right = try std.json.parseFromSlice(std.json.Value, a, right_json, .{});
    defer right.deinit();
    if (left.value != .object or right.value != .object) return error.InvalidCapsule;

    const left_events = getEvents(left.value.object) orelse return error.InvalidCapsule;
    const right_events = getEvents(right.value.object) orelse return error.InvalidCapsule;

    var keys = std.array_list.Managed(EventKey).init(a);
    defer keys.deinit();

    try collectKeys(a, &keys, left_events);
    try collectKeys(a, &keys, right_events);

    var first_diff_index: ?usize = null;
    var first_diff_key: ?EventKey = null;
    var first_diff_occurrence: ?usize = null;
    var aligned_index: usize = 0;
    var left_event_at_diff: ?std.json.Value = null;
    var right_event_at_diff: ?std.json.Value = null;

    for (keys.items) |key| {
        var left_matches = std.array_list.Managed(std.json.Value).init(a);
        defer left_matches.deinit();
        try collectEventsForKey(&left_matches, left_events, key);

        var right_matches = std.array_list.Managed(std.json.Value).init(a);
        defer right_matches.deinit();
        try collectEventsForKey(&right_matches, right_events, key);

        const max_count = @max(left_matches.items.len, right_matches.items.len);
        var occurrence: usize = 0;
        while (occurrence < max_count) : (occurrence += 1) {
            const left_event = if (occurrence < left_matches.items.len) left_matches.items[occurrence] else null;
            const right_event = if (occurrence < right_matches.items.len) right_matches.items[occurrence] else null;

            if (!alignedPairEqual(a, left_event, right_event)) {
                if (first_diff_index == null) {
                    first_diff_index = aligned_index;
                    first_diff_key = key;
                    first_diff_occurrence = occurrence;
                    left_event_at_diff = left_event;
                    right_event_at_diff = right_event;
                }
            }
            aligned_index += 1;
        }
    }

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("equal");
    try stream.write(first_diff_index == null);
    try stream.objectField("aligned_by");
    try stream.write("kind+turn+occurrence");
    try stream.objectField("left_event_count");
    try stream.write(left_events.len);
    try stream.objectField("right_event_count");
    try stream.write(right_events.len);
    try stream.objectField("aligned_count");
    try stream.write(aligned_index);
    try stream.objectField("first_diff_index");
    try stream.write(first_diff_index);

    if (first_diff_index != null) {
        try stream.objectField("first_diff");
        try stream.beginObject();
        try stream.objectField("kind");
        try stream.write(first_diff_key.?.kind);
        try stream.objectField("turn");
        try stream.write(first_diff_key.?.turn);
        try stream.objectField("occurrence");
        try stream.write(first_diff_occurrence.?);
        try stream.endObject();

        try stream.objectField("left_event");
        if (left_event_at_diff) |ev| {
            try stream.write(ev);
        } else {
            try stream.write(null);
        }

        try stream.objectField("right_event");
        if (right_event_at_diff) |ev| {
            try stream.write(ev);
        } else {
            try stream.write(null);
        }
    }

    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn collectKeys(a: std.mem.Allocator, keys: *std.array_list.Managed(EventKey), events: []const std.json.Value) !void {
    _ = a;
    for (events) |ev| {
        const key = eventKey(ev) orelse continue;
        if (containsKey(keys.items, key)) continue;
        try keys.append(key);
    }
}

fn collectEventsForKey(out: *std.array_list.Managed(std.json.Value), events: []const std.json.Value, key: EventKey) !void {
    for (events) |ev| {
        const ev_key = eventKey(ev) orelse continue;
        if (!keyEq(ev_key, key)) continue;
        try out.append(ev);
    }
}

fn alignedPairEqual(a: std.mem.Allocator, left_event: ?std.json.Value, right_event: ?std.json.Value) bool {
    if (left_event == null and right_event == null) return true;
    if (left_event == null or right_event == null) return false;

    const left_payload = eventPayload(left_event.?) orelse return false;
    const right_payload = eventPayload(right_event.?) orelse return false;
    return jsonValueEq(a, left_payload, right_payload);
}

fn getEvents(obj: std.json.ObjectMap) ?[]const std.json.Value {
    const v = obj.get("events") orelse return null;
    if (v != .array) return null;
    return v.array.items;
}

fn eventKey(ev: std.json.Value) ?EventKey {
    if (ev != .object) return null;

    const kind_v = ev.object.get("kind") orelse return null;
    if (kind_v != .string) return null;

    const turn_v = ev.object.get("turn") orelse return null;
    const turn: ?i64 = switch (turn_v) {
        .null => null,
        .integer => |i| i,
        else => return null,
    };

    return .{
        .kind = kind_v.string,
        .turn = turn,
    };
}

fn eventPayload(ev: std.json.Value) ?std.json.Value {
    if (ev != .object) return null;
    return ev.object.get("payload");
}

fn containsKey(keys: []const EventKey, needle: EventKey) bool {
    for (keys) |key| {
        if (keyEq(key, needle)) return true;
    }
    return false;
}

fn keyEq(a: EventKey, b: EventKey) bool {
    if (!std.mem.eql(u8, a.kind, b.kind)) return false;
    if (a.turn == null and b.turn == null) return true;
    if (a.turn == null or b.turn == null) return false;
    return a.turn.? == b.turn.?;
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
