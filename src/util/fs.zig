const std = @import("std");

pub const PathError = error{
    PathOutsideRoot,
    EmptyPath,
};

/// Resolve path components (collapsing `.`, `..`, and redundant separators)
/// without touching the filesystem. Returns an owned slice.
///
/// This is a pure string operation - it does NOT resolve symlinks.
/// For symlink-safe validation, combine with a filesystem-level check.
pub fn resolveComponents(a: std.mem.Allocator, path: []const u8) ![]u8 {
    if (path.len == 0) return error.EmptyPath;

    const is_absolute = path[0] == '/';
    var parts = std.array_list.Managed([]const u8).init(a);
    defer parts.deinit();

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (parts.items.len > 0) {
                _ = parts.pop();
            }
            // For absolute paths, ".." at root is a no-op (stays at /).
            // For relative paths, we silently drop it (conservative).
            continue;
        }
        try parts.append(seg);
    }

    // Reassemble
    var len: usize = 0;
    if (is_absolute) len += 1; // leading /
    for (parts.items, 0..) |seg, i| {
        if (i > 0) len += 1; // separator
        len += seg.len;
    }
    if (len == 0) {
        // Was "/" or "." or ".." - return "/"
        const out = try a.alloc(u8, 1);
        out[0] = '/';
        return out;
    }

    const out = try a.alloc(u8, len);
    var pos: usize = 0;
    if (is_absolute) {
        out[0] = '/';
        pos = 1;
    }
    for (parts.items, 0..) |seg, i| {
        if (i > 0) {
            out[pos] = '/';
            pos += 1;
        }
        @memcpy(out[pos..][0..seg.len], seg);
        pos += seg.len;
    }

    return out;
}

/// Check whether `path` is safely contained within `root`.
///
/// Both paths are normalized (component resolution) before comparison.
/// The path must either equal root exactly or start with root followed by '/'.
///
/// Returns the normalized path on success, or PathOutsideRoot if the path
/// escapes the root boundary.
pub fn validatePathUnderRoot(a: std.mem.Allocator, root: []const u8, path: []const u8) ![]u8 {
    const norm_root = try resolveComponents(a, root);
    defer a.free(norm_root);

    const norm_path = try resolveComponents(a, path);

    // Exact match: path IS the root
    if (std.mem.eql(u8, norm_path, norm_root)) return norm_path;

    // Path must start with root + "/"
    if (norm_path.len > norm_root.len and
        std.mem.startsWith(u8, norm_path, norm_root))
    {
        // Check directory boundary: next char after root prefix must be '/'
        // Special case: root is "/" (length 1), everything under it is valid
        if (norm_root.len == 1 and norm_root[0] == '/') return norm_path;
        if (norm_path[norm_root.len] == '/') return norm_path;
    }

    // Path is outside root - free it before returning error
    a.free(norm_path);
    return PathError.PathOutsideRoot;
}
