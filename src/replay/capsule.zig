const std = @import("std");

pub fn capsulePathAlloc(a: std.mem.Allocator, workspace_root: []const u8, request_id: []const u8) ![]u8 {
    const filename = try std.fmt.allocPrint(a, "{s}.json", .{request_id});
    defer a.free(filename);
    return std.fs.path.join(a, &.{ workspace_root, ".zigclaw", "capsules", filename });
}

pub fn readCapsuleJsonAlloc(a: std.mem.Allocator, io: std.Io, workspace_root: []const u8, request_id: []const u8) ![]u8 {
    const path = try capsulePathAlloc(a, workspace_root, request_id);
    defer a.free(path);
    return std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(8 * 1024 * 1024));
}
