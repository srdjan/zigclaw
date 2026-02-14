const std = @import("std");
const recall_mod = @import("recall.zig");

pub const MarkdownMemory = struct {
    root: []const u8,

    pub fn init(a: std.mem.Allocator, root_path: []const u8) !MarkdownMemory {
        // Ensure dir exists
        try std.fs.cwd().makePath(root_path);
        return .{ .root = try a.dupe(u8, root_path) };
    }

    pub fn deinit(self: *MarkdownMemory, a: std.mem.Allocator) void {
        a.free(self.root);
    }

    pub fn recall(self: *MarkdownMemory, a: std.mem.Allocator, query: []const u8, limit: usize) ![]recall_mod.MemoryItem {
        // Scaffold: reads MEMORY.md if present and performs keyword scoring.
        const mem_path = try std.fmt.allocPrint(a, "{s}/MEMORY.md", .{self.root});
        defer a.free(mem_path);

        const file = std.fs.cwd().openFile(mem_path, .{}) catch {
            return try recall_mod.empty(a);
        };
        defer file.close();

        const max = 256 * 1024;
        const content = try file.readToEndAlloc(a, max);
        defer a.free(content);

        return try recall_mod.scoreMarkdown(a, content, query, limit);
    }
};
