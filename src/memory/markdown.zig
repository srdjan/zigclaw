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
        // Scaffold: reads MEMORY.md if present and performs keyword scoring.
        const mem_path = try std.fmt.allocPrint(a, "{s}/MEMORY.md", .{self.root});
        defer a.free(mem_path);

        const max = 256 * 1024;
        const content = std.Io.Dir.cwd().readFileAlloc(io, mem_path, a, std.Io.Limit.limited(max)) catch {
            return try recall_mod.empty(a);
        };
        defer a.free(content);

        return try recall_mod.scoreMarkdown(a, content, query, limit);
    }
};
