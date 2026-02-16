const std = @import("std");

pub const CapabilityView = struct {
    tools: []const []const u8,
    allow_network: bool,
    write_paths: []const []const u8,
};

pub const OwnedIntersection = struct {
    tools: []const []const u8,
    allow_network: bool,
    write_paths: []const []const u8,

    pub fn deinit(self: *OwnedIntersection, a: std.mem.Allocator) void {
        for (self.tools) |tool| a.free(tool);
        a.free(self.tools);
        for (self.write_paths) |path| a.free(path);
        a.free(self.write_paths);
    }
};

pub fn isSubsetOf(child: CapabilityView, parent: CapabilityView) bool {
    if (child.allow_network and !parent.allow_network) return false;

    for (child.tools) |tool| {
        if (!containsStr(parent.tools, tool)) return false;
    }

    for (child.write_paths) |path| {
        var covered = false;
        for (parent.write_paths) |parent_path| {
            if (pathWithin(path, parent_path)) {
                covered = true;
                break;
            }
        }
        if (!covered) return false;
    }

    return true;
}

pub fn intersectAlloc(
    a: std.mem.Allocator,
    parent: CapabilityView,
    child: CapabilityView,
) !OwnedIntersection {
    const tools = try intersectToolSlicesAlloc(a, parent.tools, child.tools);
    errdefer freeStrSlice(a, tools);

    const write_paths = try intersectWritePathSlicesAlloc(a, parent.write_paths, child.write_paths);
    errdefer freeStrSlice(a, write_paths);

    return .{
        .tools = tools,
        .allow_network = parent.allow_network and child.allow_network,
        .write_paths = write_paths,
    };
}

fn intersectToolSlicesAlloc(
    a: std.mem.Allocator,
    parent_tools: []const []const u8,
    child_tools: []const []const u8,
) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |tool| a.free(tool);
        out.deinit();
    }

    for (child_tools) |tool| {
        if (!containsStr(parent_tools, tool)) continue;
        if (containsStr(out.items, tool)) continue;
        try out.append(try a.dupe(u8, tool));
    }

    return try out.toOwnedSlice();
}

fn intersectWritePathSlicesAlloc(
    a: std.mem.Allocator,
    parent_paths: []const []const u8,
    child_paths: []const []const u8,
) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |path| a.free(path);
        out.deinit();
    }

    for (child_paths) |child_path| {
        for (parent_paths) |parent_path| {
            const narrowed = narrowPathIntersection(child_path, parent_path) orelse continue;
            if (containsEquivalentPath(out.items, narrowed)) continue;
            try out.append(try a.dupe(u8, narrowed));
        }
    }

    return try out.toOwnedSlice();
}

fn freeStrSlice(a: std.mem.Allocator, items: []const []const u8) void {
    for (items) |item| a.free(item);
    a.free(items);
}

fn containsStr(items: []const []const u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn normalizePathForCompare(path: []const u8) []const u8 {
    var s = std.mem.trim(u8, path, " \t\r\n");
    while (std.mem.startsWith(u8, s, "./")) s = s[2..];
    while (s.len > 1 and s[s.len - 1] == '/') s = s[0 .. s.len - 1];
    return s;
}

fn isParentEscape(path: []const u8) bool {
    if (std.mem.eql(u8, path, "..")) return true;
    if (std.mem.startsWith(u8, path, "../")) return true;
    return false;
}

fn pathWithin(path: []const u8, root: []const u8) bool {
    const p = normalizePathForCompare(path);
    const r = normalizePathForCompare(root);

    if (r.len == 0 or std.mem.eql(u8, r, ".")) {
        if (p.len == 0 or std.mem.eql(u8, p, ".")) return true;
        if (std.mem.startsWith(u8, p, "/")) return false;
        if (isParentEscape(p)) return false;
        return true;
    }

    if (std.mem.eql(u8, p, r)) return true;

    if (p.len > r.len and std.mem.startsWith(u8, p, r)) {
        if (r.len == 1 and r[0] == '/') return true;
        return p[r.len] == '/';
    }

    return false;
}

fn narrowPathIntersection(a_path: []const u8, b_path: []const u8) ?[]const u8 {
    if (pathWithin(a_path, b_path)) return a_path;
    if (pathWithin(b_path, a_path)) return b_path;
    return null;
}

fn containsEquivalentPath(paths: []const []const u8, path: []const u8) bool {
    for (paths) |candidate| {
        if (pathWithin(candidate, path) and pathWithin(path, candidate)) return true;
    }
    return false;
}
