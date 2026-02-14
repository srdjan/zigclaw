const std = @import("std");

pub const FileEntry = struct {
    rel_path: []const u8,
    size: u64,
    sha256_hex: []const u8, // 64 chars

    pub fn deinit(self: *FileEntry, a: std.mem.Allocator) void {
        a.free(self.rel_path);
        a.free(self.sha256_hex);
    }
};

pub const WorkspaceSnapshot = struct {
    root: []const u8,
    files: []FileEntry,
    skipped_large_files: usize,

    pub fn deinit(self: *WorkspaceSnapshot, a: std.mem.Allocator) void {
        for (self.files) |*f| f.deinit(a);
        a.free(self.files);
        a.free(self.root);
    }
};

pub const ScanOptions = struct {
    max_files: usize = 200,
    max_file_bytes: u64 = 256 * 1024,
};

pub fn scan(a: std.mem.Allocator, workspace_root: []const u8, opts: ScanOptions) !WorkspaceSnapshot {
    const root_dupe = try a.dupe(u8, workspace_root);

    // Collect all file rel paths first
    var paths = std.ArrayList([]const u8).init(a);
    errdefer {
        for (paths.items) |p| a.free(p);
        paths.deinit();
        a.free(root_dupe);
    }

    var skipped_large: usize = 0;

    try walkCollect(a, workspace_root, "", &paths);

    // stable sort
    std.sort.block([]const u8, paths.items, {}, struct {
        fn lt(_: void, a_: []const u8, b_: []const u8) bool {
            return std.mem.lessThan(u8, a_, b_);
        }
    }.lt);

    // Build entries up to max_files (stable)
    const take = @min(opts.max_files, paths.items.len);
    var files = std.ArrayList(FileEntry).init(a);
    errdefer {
        for (files.items) |*f| f.deinit(a);
        files.deinit();
        for (paths.items) |p| a.free(p);
        paths.deinit();
        a.free(root_dupe);
    }

    for (paths.items[0..take]) |rel| {
        const full = try std.fs.path.join(a, &.{ workspace_root, rel });
        defer a.free(full);

        const st = std.fs.cwd().statFile(full) catch |e| {
            _ = e;
            continue;
        };

        if (st.size > opts.max_file_bytes) {
            skipped_large += 1;
            continue;
        }

        const hash_hex = try sha256FileHex(a, full);
        try files.append(.{
            .rel_path = try a.dupe(u8, rel),
            .size = st.size,
            .sha256_hex = hash_hex,
        });
    }

    // cleanup collected paths
    for (paths.items) |p| a.free(p);
    paths.deinit();

    return .{
        .root = root_dupe,
        .files = try files.toOwnedSlice(),
        .skipped_large_files = skipped_large,
    };
}

fn walkCollect(a: std.mem.Allocator, workspace_root: []const u8, rel_prefix: []const u8, out: *std.ArrayList([]const u8)) !void {
    const dir_path = if (rel_prefix.len == 0)
        workspace_root
    else
        try std.fs.path.join(a, &.{ workspace_root, rel_prefix });
    defer if (rel_prefix.len != 0) a.free(dir_path);

    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |e| {
        const name = e.name;

        if (e.kind == .directory) {
            if (isIgnoredDir(name)) continue;
            const next_rel = if (rel_prefix.len == 0)
                try a.dupe(u8, name)
            else
                try std.fs.path.join(a, &.{ rel_prefix, name });
            defer a.free(next_rel);

            try walkCollect(a, workspace_root, next_rel, out);
            continue;
        }

        if (e.kind != .file) continue;
        if (isIgnoredFile(name)) continue;

        const rel = if (rel_prefix.len == 0)
            try a.dupe(u8, name)
        else
            try std.fs.path.join(a, &.{ rel_prefix, name });

        // normalize separators to '/' for stable output across OS
        const norm = try normalizeSlashes(a, rel);
        a.free(rel);
        try out.append(norm);
    }
}

fn isIgnoredDir(name: []const u8) bool {
    return std.mem.eql(u8, name, ".git") or
        std.mem.eql(u8, name, ".zigclaw") or
        std.mem.eql(u8, name, "zig-out") or
        std.mem.eql(u8, name, "node_modules") or
        std.mem.eql(u8, name, "target") or
        std.mem.eql(u8, name, ".cache");
}

fn isIgnoredFile(name: []const u8) bool {
    return std.mem.eql(u8, name, ".DS_Store") or std.mem.eql(u8, name, "Thumbs.db");
}

fn normalizeSlashes(a: std.mem.Allocator, p: []const u8) ![]const u8 {
    var out = try a.dupe(u8, p);
    for (out) |*c| if (c.* == '\\') c.* = '/';
    return out;
}

fn sha256FileHex(a: std.mem.Allocator, path: []const u8) ![]const u8 {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try file.reader().read(&buf);
        if (n == 0) break;
        h.update(buf[0..n]);
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
