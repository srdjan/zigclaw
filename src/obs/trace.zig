const std = @import("std");

pub const RequestId = struct {
    hex32: [32]u8,

    pub fn slice(self: *const RequestId) []const u8 {
        return self.hex32[0..];
    }
};

pub fn newRequestId() RequestId {
    var raw: [16]u8 = undefined;
    std.crypto.random.bytes(&raw);

    var out: [32]u8 = undefined;
    const hex = "0123456789abcdef";
    for (raw, 0..) |b, i| {
        out[i*2] = hex[(b >> 4) & 0xF];
        out[i*2 + 1] = hex[b & 0xF];
    }
    return .{ .hex32 = out };
}
