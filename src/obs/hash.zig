const std = @import("std");

pub fn sha256HexAlloc(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(bytes);
    var digest: [32]u8 = undefined;
    h.final(&digest);

    var out = try a.alloc(u8, 64);
    const hex = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i*2] = hex[(b >> 4) & 0xF];
        out[i*2 + 1] = hex[b & 0xF];
    }
    return out;
}
