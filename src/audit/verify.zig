const std = @import("std");
const ledger_mod = @import("../attestation/ledger.zig");
const hash_mod = @import("../obs/hash.zig");

pub const EventVerifyStatus = struct {
    index: usize,
    valid: bool,
    leaf_hash: [64]u8,
};

pub const VerifyResult = struct {
    overall_valid: bool,
    root_matches: bool,
    expected_root: [64]u8,
    computed_root: [64]u8,
    event_count: usize,
    event_statuses: []EventVerifyStatus,

    pub fn deinit(self: *VerifyResult, a: std.mem.Allocator) void {
        a.free(self.event_statuses);
    }
};

pub fn verifyAllEvents(a: std.mem.Allocator, receipt_json: []const u8) !VerifyResult {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, receipt_json, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidReceipt;
    const obj = parsed.value.object;

    const expected_root_hex = blk: {
        const v = obj.get("merkle_root_hex") orelse return error.InvalidReceipt;
        if (v != .string or v.string.len != 64) return error.InvalidReceipt;
        break :blk v.string;
    };
    const expected_root = try parseHexDigest32(expected_root_hex);

    const ev_hashes_v = obj.get("event_hashes") orelse return error.InvalidReceipt;
    if (ev_hashes_v != .array) return error.InvalidReceipt;
    const ev_hashes_arr = ev_hashes_v.array.items;

    // Rebuild Merkle tree from event hashes
    var tree = ledger_mod.MerkleTree.init(a);
    defer tree.deinit();

    for (ev_hashes_arr) |v| {
        if (v != .string or v.string.len != 64) return error.InvalidReceipt;
        try tree.addLeafHash(try parseHexDigest32(v.string));
    }

    const computed_root = try tree.computeRoot();
    var computed_root_hex: [64]u8 = undefined;
    hash_mod.hexBuf(&computed_root, computed_root_hex[0..]);

    var expected_root_hex_buf: [64]u8 = undefined;
    @memcpy(&expected_root_hex_buf, expected_root_hex);

    const root_matches = std.mem.eql(u8, &computed_root, &expected_root);

    // Verify each event
    var statuses = try a.alloc(EventVerifyStatus, ev_hashes_arr.len);
    errdefer a.free(statuses);

    var all_valid = root_matches;
    for (ev_hashes_arr, 0..) |_, i| {
        var proof = try tree.proof(i);
        defer proof.deinit(a);

        const valid = ledger_mod.verifyProof(proof, expected_root);
        if (!valid) all_valid = false;

        var leaf_hex: [64]u8 = undefined;
        hash_mod.hexBuf(&proof.leaf_hash, leaf_hex[0..]);

        statuses[i] = .{
            .index = i,
            .valid = valid,
            .leaf_hash = leaf_hex,
        };
    }

    return .{
        .overall_valid = all_valid,
        .root_matches = root_matches,
        .expected_root = expected_root_hex_buf,
        .computed_root = computed_root_hex,
        .event_count = ev_hashes_arr.len,
        .event_statuses = statuses,
    };
}

pub fn verifyResultJsonAlloc(a: std.mem.Allocator, result: VerifyResult) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("overall_valid");
    try stream.write(result.overall_valid);
    try stream.objectField("root_matches");
    try stream.write(result.root_matches);
    try stream.objectField("expected_root");
    try stream.write(result.expected_root[0..]);
    try stream.objectField("computed_root");
    try stream.write(result.computed_root[0..]);
    try stream.objectField("event_count");
    try stream.write(result.event_count);
    try stream.objectField("events");
    try stream.beginArray();
    for (result.event_statuses) |ev| {
        try stream.beginObject();
        try stream.objectField("index");
        try stream.write(ev.index);
        try stream.objectField("valid");
        try stream.write(ev.valid);
        try stream.objectField("leaf_hash");
        try stream.write(ev.leaf_hash[0..]);
        try stream.endObject();
    }
    try stream.endArray();
    try stream.endObject();

    return try aw.toOwnedSlice();
}

fn parseHexDigest32(hex: []const u8) ![32]u8 {
    if (hex.len != 64) return error.InvalidHex;
    var out: [32]u8 = undefined;
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const hi = try parseNibble(hex[i * 2]);
        const lo = try parseNibble(hex[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
    }
    return out;
}

fn parseNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHex,
    };
}
