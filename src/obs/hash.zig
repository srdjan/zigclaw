const std = @import("std");

const hex_chars = "0123456789abcdef";

/// Hex-encode a byte slice into a heap-allocated string. Caller owns the result.
pub fn hexAlloc(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try a.alloc(u8, bytes.len * 2);
    hexBuf(bytes, out);
    return out;
}

/// Hex-encode bytes into a pre-allocated buffer. `out.len` must be `bytes.len * 2`.
pub fn hexBuf(bytes: []const u8, out: []u8) void {
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[(b >> 4) & 0xF];
        out[i * 2 + 1] = hex_chars[b & 0xF];
    }
}

pub fn sha256HexAlloc(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(bytes);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return hexAlloc(a, &digest);
}
