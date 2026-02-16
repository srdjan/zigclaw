const std = @import("std");
const hash_mod = @import("../obs/hash.zig");
const ledger_mod = @import("ledger.zig");

pub const ExecutionReceipt = struct {
    request_id: []const u8,
    policy_hash: []const u8,
    prompt_hash: ?[]const u8,
    merkle_root_hex: [64]u8,
    event_count: usize,
    ts_start_ms: i64,
    ts_end_ms: i64,
    tool_args_hashes: []const []const u8,
    tool_output_hashes: []const []const u8,
    event_hashes: []const []const u8,

    pub fn deinit(self: *ExecutionReceipt, a: std.mem.Allocator) void {
        a.free(self.request_id);
        a.free(self.policy_hash);
        if (self.prompt_hash) |ph| a.free(ph);

        for (self.tool_args_hashes) |s| a.free(s);
        a.free(self.tool_args_hashes);

        for (self.tool_output_hashes) |s| a.free(s);
        a.free(self.tool_output_hashes);

        for (self.event_hashes) |s| a.free(s);
        a.free(self.event_hashes);
    }
};

pub fn buildFromLedger(
    a: std.mem.Allocator,
    request_id: []const u8,
    policy_hash: []const u8,
    prompt_hash: ?[]const u8,
    ts_start_ms: i64,
    ts_end_ms: i64,
    ledger: *const ledger_mod.MerkleTree,
    tool_args_hashes: []const []const u8,
    tool_output_hashes: []const []const u8,
) !ExecutionReceipt {
    const root = try ledger.computeRoot();
    var root_hex: [64]u8 = undefined;
    hash_mod.hexBuf(&root, root_hex[0..]);

    const event_hashes = try hashesHexAlloc(a, ledger.leafHashes());
    errdefer freeStrSlice(a, event_hashes);

    return .{
        .request_id = try a.dupe(u8, request_id),
        .policy_hash = try a.dupe(u8, policy_hash),
        .prompt_hash = if (prompt_hash) |ph| try a.dupe(u8, ph) else null,
        .merkle_root_hex = root_hex,
        .event_count = ledger.leafCount(),
        .ts_start_ms = ts_start_ms,
        .ts_end_ms = ts_end_ms,
        .tool_args_hashes = try dupeStrSlice(a, tool_args_hashes),
        .tool_output_hashes = try dupeStrSlice(a, tool_output_hashes),
        .event_hashes = event_hashes,
    };
}

pub fn writeReceiptFile(a: std.mem.Allocator, io: std.Io, workspace_root: []const u8, receipt: ExecutionReceipt) ![]u8 {
    const dir = try std.fs.path.join(a, &.{ workspace_root, ".zigclaw", "receipts" });
    defer a.free(dir);
    try std.Io.Dir.cwd().createDirPath(io, dir);

    const filename = try std.fmt.allocPrint(a, "{s}.json", .{receipt.request_id});
    defer a.free(filename);
    const path = try std.fs.path.join(a, &.{ dir, filename });
    errdefer a.free(path);

    const json = try toJsonAlloc(a, receipt);
    defer a.free(json);

    var f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var w = f.writer(io, &buf);
    try w.interface.writeAll(json);
    try w.interface.writeAll("\n");
    try w.flush();

    return path;
}

pub fn receiptPathAlloc(a: std.mem.Allocator, workspace_root: []const u8, request_id: []const u8) ![]u8 {
    const filename = try std.fmt.allocPrint(a, "{s}.json", .{request_id});
    defer a.free(filename);
    return std.fs.path.join(a, &.{ workspace_root, ".zigclaw", "receipts", filename });
}

pub fn readReceiptJsonAlloc(a: std.mem.Allocator, io: std.Io, workspace_root: []const u8, request_id: []const u8) ![]u8 {
    const path = try receiptPathAlloc(a, workspace_root, request_id);
    defer a.free(path);
    return std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(4 * 1024 * 1024));
}

pub fn verifyEventFromReceiptJsonAlloc(a: std.mem.Allocator, receipt_json: []const u8, event_index: usize) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, receipt_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidReceipt;

    const obj = parsed.value.object;
    const request_id = try getString(obj, "request_id");
    const expected_root_hex = try getString(obj, "merkle_root_hex");
    if (expected_root_hex.len != 64) return error.InvalidReceipt;
    const expected_root = try parseHexDigest32(expected_root_hex);

    const ev_hashes_v = obj.get("event_hashes") orelse return error.InvalidReceipt;
    if (ev_hashes_v != .array) return error.InvalidReceipt;
    const ev_hashes_arr = ev_hashes_v.array.items;
    if (event_index >= ev_hashes_arr.len) return error.EventIndexOutOfBounds;

    var tree = ledger_mod.MerkleTree.init(a);
    defer tree.deinit();

    for (ev_hashes_arr) |v| {
        if (v != .string or v.string.len != 64) return error.InvalidReceipt;
        try tree.addLeafHash(try parseHexDigest32(v.string));
    }

    const computed_root = try tree.computeRoot();
    var computed_root_hex: [64]u8 = undefined;
    hash_mod.hexBuf(&computed_root, computed_root_hex[0..]);

    var proof = try tree.proof(event_index);
    defer proof.deinit(a);

    const valid = ledger_mod.verifyProof(proof, expected_root);
    var leaf_hex: [64]u8 = undefined;
    hash_mod.hexBuf(&proof.leaf_hash, leaf_hex[0..]);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("event_index");
    try stream.write(event_index);
    try stream.objectField("valid");
    try stream.write(valid);
    try stream.objectField("expected_root");
    try stream.write(expected_root_hex);
    try stream.objectField("computed_root");
    try stream.write(computed_root_hex[0..]);
    try stream.objectField("leaf_hash");
    try stream.write(leaf_hex[0..]);
    try stream.objectField("proof");
    try stream.beginArray();
    for (proof.siblings) |sibling| {
        var sib_hex: [64]u8 = undefined;
        hash_mod.hexBuf(&sibling.hash, sib_hex[0..]);
        try stream.beginObject();
        try stream.objectField("hash");
        try stream.write(sib_hex[0..]);
        try stream.objectField("is_left");
        try stream.write(sibling.is_left);
        try stream.endObject();
    }
    try stream.endArray();
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn toJsonAlloc(a: std.mem.Allocator, receipt: ExecutionReceipt) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(receipt.request_id);
    try stream.objectField("policy_hash");
    try stream.write(receipt.policy_hash);
    try stream.objectField("prompt_hash");
    try stream.write(receipt.prompt_hash);
    try stream.objectField("merkle_root_hex");
    try stream.write(receipt.merkle_root_hex[0..]);
    try stream.objectField("event_count");
    try stream.write(receipt.event_count);
    try stream.objectField("ts_start_ms");
    try stream.write(receipt.ts_start_ms);
    try stream.objectField("ts_end_ms");
    try stream.write(receipt.ts_end_ms);

    try stream.objectField("tool_args_hashes");
    try stream.beginArray();
    for (receipt.tool_args_hashes) |h| try stream.write(h);
    try stream.endArray();

    try stream.objectField("tool_output_hashes");
    try stream.beginArray();
    for (receipt.tool_output_hashes) |h| try stream.write(h);
    try stream.endArray();

    try stream.objectField("event_hashes");
    try stream.beginArray();
    for (receipt.event_hashes) |h| try stream.write(h);
    try stream.endArray();
    try stream.endObject();

    return try aw.toOwnedSlice();
}

fn hashesHexAlloc(a: std.mem.Allocator, hashes: []const [32]u8) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |item| a.free(item);
        out.deinit();
    }
    for (hashes) |h| try out.append(try hash_mod.hexAlloc(a, &h));
    return try out.toOwnedSlice();
}

fn dupeStrSlice(a: std.mem.Allocator, input: []const []const u8) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |item| a.free(item);
        out.deinit();
    }
    for (input) |item| try out.append(try a.dupe(u8, item));
    return try out.toOwnedSlice();
}

fn freeStrSlice(a: std.mem.Allocator, input: []const []const u8) void {
    for (input) |item| a.free(item);
    a.free(input);
}

fn getString(obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const v = obj.get(key) orelse return error.InvalidReceipt;
    if (v != .string) return error.InvalidReceipt;
    return v.string;
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
