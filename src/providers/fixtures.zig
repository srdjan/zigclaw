const std = @import("std");
const provider = @import("provider.zig");
const hash_mod = @import("../obs/hash.zig");

pub const FixtureRecord = struct {
    request: provider.ChatRequest,
    response: provider.ChatResponseView,
};

pub fn requestHashHexAlloc(a: std.mem.Allocator, req: provider.ChatRequest) ![]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("model="); h.update(req.model);
    h.update(";temp="); h.update(std.mem.asBytes(&req.temperature));
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
    return hash_mod.hexAlloc(a, &digest);
}

pub fn fixturePathAlloc(a: std.mem.Allocator, dir: []const u8, hash_hex: []const u8) ![]u8 {
    return try std.fmt.allocPrint(a, "{s}/{s}.json", .{ dir, hash_hex });
}
