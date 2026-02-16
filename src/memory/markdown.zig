const std = @import("std");
const recall_mod = @import("recall.zig");

pub const MarkdownMemory = struct {
    root: []const u8,

    pub fn init(a: std.mem.Allocator, io: std.Io, root_path: []const u8) !MarkdownMemory {
        // Ensure dir exists
        try std.Io.Dir.cwd().createDirPath(io, root_path);
        return .{ .root = try a.dupe(u8, root_path) };
    }

    pub fn deinit(self: *MarkdownMemory, a: std.mem.Allocator) void {
        a.free(self.root);
    }

    pub fn recall(self: *MarkdownMemory, a: std.mem.Allocator, io: std.Io, query: []const u8, limit: usize) ![]recall_mod.MemoryItem {
        var all = std.array_list.Managed(recall_mod.MemoryItem).init(a);
        errdefer {
            for (all.items) |it| {
                a.free(it.title);
                a.free(it.snippet);
            }
            all.deinit();
        }

        const per_file_limit = @max(@as(usize, 4), limit);
        try appendScoredFile(a, io, &all, self.root, "MEMORY.md", "memory", query, per_file_limit);

        const primitive_dirs = [_][]const u8{ "tasks", "projects", "decisions", "lessons", "people" };
        for (primitive_dirs) |d| {
            const dir_path = try std.fmt.allocPrint(a, "{s}/{s}", .{ self.root, d });
            defer a.free(dir_path);

            var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch continue;
            defer dir.close(io);

            var it = dir.iterate();
            while (try it.next(io)) |ent| {
                if (ent.kind != .file) continue;
                if (!std.mem.endsWith(u8, ent.name, ".md")) continue;

                const title = try std.fmt.allocPrint(a, "{s}/{s}", .{ d, ent.name });
                defer a.free(title);
                try appendScoredFile(a, io, &all, dir_path, ent.name, title, query, per_file_limit);
            }
        }

        if (all.items.len == 0) return try recall_mod.empty(a);

        std.sort.block(recall_mod.MemoryItem, all.items, {}, struct {
            fn lt(_: void, a_: recall_mod.MemoryItem, b_: recall_mod.MemoryItem) bool {
                return a_.score > b_.score;
            }
        }.lt);

        const n = @min(limit, all.items.len);
        while (all.items.len > n) {
            const it = all.pop().?;
            a.free(it.title);
            a.free(it.snippet);
        }

        return try all.toOwnedSlice();
    }
};

fn appendScoredFile(
    a: std.mem.Allocator,
    io: std.Io,
    out: *std.array_list.Managed(recall_mod.MemoryItem),
    dir_path: []const u8,
    filename: []const u8,
    title: []const u8,
    query: []const u8,
    limit: usize,
) !void {
    const path = try std.fs.path.join(a, &.{ dir_path, filename });
    defer a.free(path);

    const max = 256 * 1024;
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(max)) catch return;
    defer a.free(content);

    const scored = try recall_mod.scoreMarkdownWithTitle(a, content, query, limit, title);
    defer a.free(scored);

    try out.appendSlice(scored);
}
