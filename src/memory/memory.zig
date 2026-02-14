const std = @import("std");
const config = @import("../config.zig");
const md = @import("markdown.zig");
const recall_mod = @import("recall.zig");

pub const MemoryItem = recall_mod.MemoryItem;

pub const MemoryBackend = union(enum) {
    markdown: md.MarkdownMemory,
    // sqlite: ... (later)

    pub fn fromConfig(a: std.mem.Allocator, cfg: config.MemoryConfig) !MemoryBackend {
        return switch (cfg.backend) {
            .markdown => .{ .markdown = try md.MarkdownMemory.init(a, cfg.root) },
            .sqlite => .{ .markdown = try md.MarkdownMemory.init(a, cfg.root) }, // fallback for scaffold
        };
    }

    pub fn deinit(self: *MemoryBackend, a: std.mem.Allocator) void {
        switch (self.*) {
            .markdown => |*m| m.deinit(a),
        }
    }

    pub fn recall(self: *MemoryBackend, a: std.mem.Allocator, query: []const u8, limit: usize) ![]MemoryItem {
        return switch (self.*) {
            .markdown => |*m| m.recall(a, query, limit),
        };
    }
};

pub fn freeRecall(a: std.mem.Allocator, items: []MemoryItem) void {
    for (items) |it| {
        a.free(it.title);
        a.free(it.snippet);
    }
    a.free(items);
}
