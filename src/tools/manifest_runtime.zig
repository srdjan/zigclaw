const std = @import("std");
const manifest = @import("manifest.zig");

pub fn listToolsJsonAlloc(a: std.mem.Allocator, plugin_dir: []const u8) ![]u8 {
    var dir = try std.fs.cwd().openDir(plugin_dir, .{ .iterate = true });
    defer dir.close();

    var tools = std.ArrayList([]const u8).init(a);
    defer {
        for (tools.items) |s| a.free(s);
        tools.deinit();
    }

    var it = dir.iterate();
    while (try it.next()) |e| {
        if (e.kind != .file) continue;
        if (!std.mem.endsWith(u8, e.name, ".toml")) continue;
        // tool name is file stem
        const stem = e.name[0 .. e.name.len - ".toml".len];
        try tools.append(try a.dupe(u8, stem));
    }

    std.sort.block([]const u8, tools.items, {}, struct {
        fn lt(_: void, a_: []const u8, b_: []const u8) bool { return std.mem.lessThan(u8, a_, b_); }
    }.lt);

    var stream = std.json.StringifyStream.init(a);
    defer stream.deinit();

    try stream.beginObject();
    try stream.objectField("tools");
    try stream.beginArray();
    for (tools.items) |t| try stream.write(t);
    try stream.endArray();
    try stream.endObject();

    return try stream.toOwnedSlice();
}

pub fn describeToolJsonAlloc(a: std.mem.Allocator, plugin_dir: []const u8, tool: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(a, "{s}/{s}.toml", .{ plugin_dir, tool });
    defer a.free(path);

    var owned = try manifest.loadManifest(a, path);
    defer owned.deinit(a);

    return try owned.manifest.toJsonAlloc(a);
}
