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

pub fn loadOrCreate(a: std.mem.Allocator, io: std.Io, workspace_root: []const u8) !TokenInfo {
    const dir = try std.fs.path.join(a, &.{ workspace_root, ".zigclaw" });
    defer a.free(dir);

    std.Io.Dir.cwd().createDirPath(io, dir) catch {};

    const path = try std.fs.path.join(a, &.{ dir, "gateway.token" });
    defer a.free(path);

    // Try load
    if (std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(4096))) |bytes| {
        defer a.free(bytes);

        const token_trim = std.mem.trim(u8, bytes, " \t\r\n");
        const token = try a.dupe(u8, token_trim);
        return .{ .token = token, .path = try a.dupe(u8, path) };
    } else |_| {
        // create
        var raw: [32]u8 = undefined;
        io.random(&raw);

        const token = try a.alloc(u8, 64);
        hash.hexBuf(&raw, token);

        var file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        defer file.close(io);

        var fbuf: [4096]u8 = undefined;
        var fw = file.writer(io, &fbuf);
        try fw.interface.print("{s}\n", .{token});
        try fw.flush();

        return .{ .token = token, .path = try a.dupe(u8, path) };
    }
}
