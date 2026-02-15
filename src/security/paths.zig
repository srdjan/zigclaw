const std = @import("std");
const fs_util = @import("../util/fs.zig");

pub const PathError = fs_util.PathError;

/// Check whether `path` is safely contained within `root`.
///
/// Both paths are normalized (collapsing "..", ".", redundant separators)
/// before comparison. The path must equal root exactly or begin with
/// root followed by a '/' separator. This prevents both directory traversal
/// ("../") and prefix confusion ("/workspace" matching "/workspaced").
///
/// Returns the normalized path on success (caller owns the allocation).
/// Returns error.PathOutsideRoot if the path escapes the root boundary.
/// Returns error.EmptyPath if either argument is empty.
pub fn isPathUnder(a: std.mem.Allocator, root: []const u8, path: []const u8) ![]u8 {
    return fs_util.validatePathUnderRoot(a, root, path);
}
