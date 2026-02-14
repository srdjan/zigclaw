const std = @import("std");

pub fn isPathUnder(root: []const u8, path: []const u8) bool {
    // Scaffold: compare normalized prefixes; replace with realpath + symlink defense.
    return std.mem.startsWith(u8, path, root);
}
