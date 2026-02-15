const std = @import("std");
const config = @import("../config.zig");
const ws = @import("workspace.zig");

pub fn buildSystemPrompt(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();

    try aw.writer.writeAll("You are ZigClaw.\n");
    try aw.writer.print("WorkspaceRoot: {s}\n", .{cfg.raw.security.workspace_root});
    try aw.writer.print("ActiveCapabilityPreset: {s}\n", .{cfg.raw.capabilities.active_preset});
    try aw.writer.print("PolicyHash: {s}\n", .{cfg.policy.policyHash()});
    try aw.writer.writeAll("Tools: WASI plugins (strict mounts, args schema).\n\n");

    // Allowed tool list (sorted)
    var tools = std.array_list.Managed([]const u8).init(a);
    defer tools.deinit();
    for (cfg.policy.active.tools) |t| try tools.append(t);
    std.sort.block([]const u8, tools.items, {}, struct {
        fn lt(_: void, a_: []const u8, b_: []const u8) bool { return std.mem.lessThan(u8, a_, b_); }
    }.lt);

    try aw.writer.writeAll("AllowedTools:\n");
    for (tools.items) |t| try aw.writer.print("- {s}\n", .{t});
    try aw.writer.writeAll("\n");

    // Workspace snapshot (stable)
    var snap = try ws.scan(a, io, cfg.raw.security.workspace_root, .{});
    defer snap.deinit(a);

    try aw.writer.print("WorkspaceSnapshot: {d} files (skipped_large={d})\n", .{ snap.files.len, snap.skipped_large_files });
    for (snap.files) |f| {
        try aw.writer.print("- {s} (size={d}, sha256={s})\n", .{ f.rel_path, f.size, f.sha256_hex });
    }
    try aw.writer.writeAll("\n");

    // Optional identity files (full content, truncated)
    try appendSpecialFile(a, io, &aw.writer, cfg.raw.security.workspace_root, "AGENTS.md", 16 * 1024);
    try appendSpecialFile(a, io, &aw.writer, cfg.raw.security.workspace_root, "SOUL.md", 16 * 1024);
    try appendSpecialFile(a, io, &aw.writer, cfg.raw.security.workspace_root, "TOOLS.md", 16 * 1024);

    return try aw.toOwnedSlice();
}

fn appendSpecialFile(a: std.mem.Allocator, io: std.Io, w: *std.Io.Writer, workspace_root: []const u8, name: []const u8, max_bytes: usize) !void {
    const path = try std.fs.path.join(a, &.{ workspace_root, name });
    defer a.free(path);

    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(max_bytes)) catch return;
    defer a.free(bytes);

    try w.print("=== {s} ===\n", .{name});
    try w.writeAll(bytes);
    if (bytes.len == max_bytes) try w.writeAll("\n... (truncated)\n");
    try w.writeAll("\n");
}
