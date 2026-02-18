const std = @import("std");
const manifest = @import("manifest.zig");
const registry_mod = @import("registry.zig");

pub fn listToolsJsonAlloc(a: std.mem.Allocator, io: std.Io, plugin_dir: []const u8, external_dir: []const u8) ![]u8 {
    var tools = std.array_list.Managed([]const u8).init(a);
    defer {
        for (tools.items) |s| a.free(s);
        tools.deinit();
    }

    // Scan built-in plugin_dir
    try collectTomlStems(a, io, plugin_dir, &tools);

    // Scan external_dir (best-effort: directory may not exist)
    collectTomlStems(a, io, external_dir, &tools) catch {};

    std.sort.block([]const u8, tools.items, {}, struct {
        fn lt(_: void, a_: []const u8, b_: []const u8) bool { return std.mem.lessThan(u8, a_, b_); }
    }.lt);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("tools");
    try stream.beginArray();
    for (tools.items) |t| try stream.write(t);
    try stream.endArray();
    try stream.endObject();

    return try aw.toOwnedSlice();
}

fn collectTomlStems(a: std.mem.Allocator, io: std.Io, dir_path: []const u8, tools: *std.array_list.Managed([]const u8)) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file) continue;
        if (!std.mem.endsWith(u8, e.name, ".toml")) continue;
        const stem = e.name[0 .. e.name.len - ".toml".len];
        try tools.append(try a.dupe(u8, stem));
    }
}

pub fn describeToolJsonAlloc(a: std.mem.Allocator, io: std.Io, plugin_dir: []const u8, external_dir: []const u8, tool: []const u8) ![]u8 {
    // Resolve directory: built-in tools from plugin_dir, external from external_dir
    const tool_dir = if (registry_mod.isBuiltin(tool)) plugin_dir else external_dir;
    const path = try std.fmt.allocPrint(a, "{s}/{s}.toml", .{ tool_dir, tool });
    defer a.free(path);

    var owned = try manifest.loadManifest(a, io, path);
    defer owned.deinit(a);

    return try owned.manifest.toJsonAlloc(a);
}
