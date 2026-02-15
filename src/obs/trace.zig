const std = @import("std");
const hash = @import("hash.zig");

pub const RequestId = struct {
    hex32: [32]u8,

    pub fn slice(self: *const RequestId) []const u8 {
        return self.hex32[0..];
    }
};

pub fn newRequestId(io: std.Io) RequestId {
    var raw: [16]u8 = undefined;
    io.random(&raw);

    var out: [32]u8 = undefined;
    hash.hexBuf(&raw, &out);
    return .{ .hex32 = out };
}
