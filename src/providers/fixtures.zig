const std = @import("std");
const provider = @import("provider.zig");

pub const FixtureRecord = struct {
    request: provider.ChatRequest,
    response: provider.ChatResponseView,
};

pub fn requestHashHexAlloc(a: std.mem.Allocator, req: provider.ChatRequest) ![]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("model="); h.update(req.model);
    h.update(";temp="); h.updateFloat(req.temperature);
    h.update(";system=");
    if (req.system) |s| h.update(s);
    h.update(";user="); h.update(req.user);
    h.update(";memory=");
    for (req.memory_context) |m| {
        h.update("|t="); h.update(m.title);
        h.update("|s="); h.update(m.snippet);
    }
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

pub fn fixturePathAlloc(a: std.mem.Allocator, dir: []const u8, hash_hex: []const u8) ![]u8 {
    return try std.fmt.allocPrint(a, "{s}/{s}.json", .{ dir, hash_hex });
}
