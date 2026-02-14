const std = @import("std");
const hash = @import("../obs/hash.zig");

pub const TokenInfo = struct {
    token: []u8,
    path: []u8,

    pub fn deinit(self: *TokenInfo, a: std.mem.Allocator) void {
        a.free(self.token);
        a.free(self.path);
    }
};

pub fn loadOrCreate(a: std.mem.Allocator, workspace_root: []const u8) !TokenInfo {
    const dir = try std.fs.path.join(a, &.{ workspace_root, ".zigclaw" });
    defer a.free(dir);

    std.fs.cwd().makePath(dir) catch {};

    const path = try std.fs.path.join(a, &.{ dir, "gateway.token" });
    defer a.free(path);

    // Try load
    if (std.fs.cwd().openFile(path, .{})) |file| {
        defer file.close();
        const bytes = try file.readToEndAlloc(a, 4096);
        errdefer a.free(bytes);

        const token_trim = std.mem.trim(u8, bytes, " \t\r\n");
        const token = try a.dupe(u8, token_trim);
        a.free(bytes);
        return .{ .token = token, .path = try a.dupe(u8, path) };
    } else |_| {
        // create
        var raw: [32]u8 = undefined;
        std.crypto.random.bytes(&raw);

        const token = try a.alloc(u8, 64);
        hash.hexBuf(&raw, token);

        var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writer().print("{s}\n", .{token});

        return .{ .token = token, .path = try a.dupe(u8, path) };
    }
}
