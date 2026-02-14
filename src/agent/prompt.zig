const std = @import("std");
const config = @import("../config.zig");
const ws = @import("workspace.zig");

pub fn buildSystemPrompt(a: std.mem.Allocator, cfg: config.ValidatedConfig) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();

    try out.writer().writeAll("You are ZigClaw.\n");
    try out.writer().print("WorkspaceRoot: {s}\n", .{cfg.raw.security.workspace_root});
    try out.writer().print("ActiveCapabilityPreset: {s}\n", .{cfg.raw.capabilities.active_preset});
    try out.writer().print("PolicyHash: {s}\n", .{cfg.policy.policyHash()});
    try out.writer().writeAll("Tools: WASI plugins (strict mounts, args schema).\n\n");

    // Allowed tool list (sorted)
    var tools = std.ArrayList([]const u8).init(a);
    defer tools.deinit();
    for (cfg.policy.active.tools) |t| try tools.append(t);
    std.sort.block([]const u8, tools.items, {}, struct {
        fn lt(_: void, a_: []const u8, b_: []const u8) bool { return std.mem.lessThan(u8, a_, b_); }
    }.lt);

    try out.writer().writeAll("AllowedTools:\n");
    for (tools.items) |t| try out.writer().print("- {s}\n", .{t});
    try out.writer().writeAll("\n");

    // Workspace snapshot (stable)
    const snap = try ws.scan(a, cfg.raw.security.workspace_root, .{});
    defer snap.deinit(a);

    try out.writer().print("WorkspaceSnapshot: {d} files (skipped_large={d})\n", .{snap.files.len, snap.skipped_large_files});
    for (snap.files) |f| {
        try out.writer().print("- {s} (size={d}, sha256={s})\n", .{f.rel_path, f.size, f.sha256_hex});
    }
    try out.writer().writeAll("\n");

    // Optional identity files (full content, truncated)
    try appendSpecialFile(a, &out, cfg.raw.security.workspace_root, "AGENTS.md", 16 * 1024);
    try appendSpecialFile(a, &out, cfg.raw.security.workspace_root, "SOUL.md", 16 * 1024);
    try appendSpecialFile(a, &out, cfg.raw.security.workspace_root, "TOOLS.md", 16 * 1024);

    return try out.toOwnedSlice();
}

fn appendSpecialFile(a: std.mem.Allocator, out: *std.ArrayList(u8), workspace_root: []const u8, name: []const u8, max_bytes: usize) !void {
    const path = try std.fs.path.join(a, &.{ workspace_root, name });
    defer a.free(path);

    const file = std.fs.cwd().openFile(path, .{}) catch return;
    defer file.close();

    const bytes = file.readToEndAlloc(a, max_bytes) catch return;
    defer a.free(bytes);

    try out.writer().print("=== {s} ===\n", .{name});
    try out.writer().writeAll(bytes);
    if (bytes.len == max_bytes) try out.writer().writeAll("\n... (truncated)\n");
    try out.writer().writeAll("\n");
}
