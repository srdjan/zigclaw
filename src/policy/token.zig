const std = @import("std");
const hash_mod = @import("../obs/hash.zig");

pub const ParentCapabilities = struct {
    allowed_tools: []const []const u8,
    write_paths: []const []const u8,
    allow_network: bool,
};

pub const RequestedScope = struct {
    allowed_tools: ?[]const []const u8 = null,
    write_paths: ?[]const []const u8 = null,
    allow_network: ?bool = null,
    max_turns: ?usize = null,
    expiry_ms: ?i64 = null,
};

pub const CapabilityToken = struct {
    allowed_tools: []const []const u8,
    write_paths: []const []const u8,
    allow_network: bool,
    max_turns: ?usize = null,
    expiry_ms: ?i64 = null,
    token_hash: [64]u8,

    pub fn deinit(self: *CapabilityToken, a: std.mem.Allocator) void {
        for (self.allowed_tools) |tool| a.free(tool);
        a.free(self.allowed_tools);

        for (self.write_paths) |path| a.free(path);
        a.free(self.write_paths);
    }

    pub fn isExpired(self: CapabilityToken, now_ms: i64) bool {
        const expiry = self.expiry_ms orelse return false;
        return now_ms >= expiry;
    }

    pub fn isWithinTurnLimit(self: CapabilityToken, current_turn: usize) bool {
        const max_turns = self.max_turns orelse return true;
        return current_turn < max_turns;
    }
};

pub fn mint(a: std.mem.Allocator, parent: ParentCapabilities, requested_scope: RequestedScope) !CapabilityToken {
    const allowed_tools = try clampToolsAlloc(a, parent.allowed_tools, requested_scope.allowed_tools);
    errdefer freeStrSlice(a, allowed_tools);

    const write_paths = try clampWritePathsAlloc(a, parent.write_paths, requested_scope.write_paths);
    errdefer freeStrSlice(a, write_paths);

    var token = CapabilityToken{
        .allowed_tools = allowed_tools,
        .write_paths = write_paths,
        .allow_network = parent.allow_network and (requested_scope.allow_network orelse parent.allow_network),
        .max_turns = requested_scope.max_turns,
        .expiry_ms = requested_scope.expiry_ms,
        .token_hash = undefined,
    };
    token.token_hash = try computeTokenHash(a, token);
    return token;
}

fn clampToolsAlloc(
    a: std.mem.Allocator,
    parent_tools: []const []const u8,
    requested_tools: ?[]const []const u8,
) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |tool| a.free(tool);
        out.deinit();
    }

    if (requested_tools) |requested| {
        for (requested) |tool| {
            if (!containsStr(parent_tools, tool)) continue;
            if (containsStr(out.items, tool)) continue;
            try out.append(try a.dupe(u8, tool));
        }
    } else {
        for (parent_tools) |tool| {
            try out.append(try a.dupe(u8, tool));
        }
    }
    return try out.toOwnedSlice();
}

fn clampWritePathsAlloc(
    a: std.mem.Allocator,
    parent_paths: []const []const u8,
    requested_paths: ?[]const []const u8,
) ![]const []const u8 {
    if (requested_paths == null) return dupeStrSlice(a, parent_paths);

    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |path| a.free(path);
        out.deinit();
    }

    for (requested_paths.?) |requested| {
        for (parent_paths) |parent| {
            const narrowed = narrowPathIntersection(requested, parent) orelse continue;
            if (containsEquivalentPath(out.items, narrowed)) continue;
            try out.append(try a.dupe(u8, narrowed));
        }
    }
    return try out.toOwnedSlice();
}

fn computeTokenHash(a: std.mem.Allocator, token: CapabilityToken) ![64]u8 {
    const tool_idxs = try a.alloc(usize, token.allowed_tools.len);
    defer a.free(tool_idxs);
    for (tool_idxs, 0..) |*idx, i| idx.* = i;
    std.sort.block(usize, tool_idxs, token.allowed_tools, struct {
        fn lessThan(tools: []const []const u8, ai: usize, bi: usize) bool {
            return std.mem.lessThan(u8, tools[ai], tools[bi]);
        }
    }.lessThan);

    const write_idxs = try a.alloc(usize, token.write_paths.len);
    defer a.free(write_idxs);
    for (write_idxs, 0..) |*idx, i| idx.* = i;
    std.sort.block(usize, write_idxs, token.write_paths, struct {
        fn lessThan(paths: []const []const u8, ai: usize, bi: usize) bool {
            return std.mem.lessThan(u8, paths[ai], paths[bi]);
        }
    }.lessThan);

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("allow_network=");
    h.update(if (token.allow_network) "true" else "false");
    h.update(";max_turns=");
    if (token.max_turns) |mt| {
        const txt = try std.fmt.allocPrint(a, "{d}", .{mt});
        defer a.free(txt);
        h.update(txt);
    } else {
        h.update("none");
    }
    h.update(";expiry_ms=");
    if (token.expiry_ms) |expiry| {
        const txt = try std.fmt.allocPrint(a, "{d}", .{expiry});
        defer a.free(txt);
        h.update(txt);
    } else {
        h.update("none");
    }

    h.update(";tools=");
    for (tool_idxs) |idx| {
        h.update(token.allowed_tools[idx]);
        h.update(",");
    }

    h.update(";write_paths=");
    for (write_idxs) |idx| {
        h.update(token.write_paths[idx]);
        h.update(",");
    }

    var digest: [32]u8 = undefined;
    h.final(&digest);

    var hash_hex: [64]u8 = undefined;
    hash_mod.hexBuf(&digest, hash_hex[0..]);
    return hash_hex;
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

fn containsStr(items: []const []const u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn dupeStrSlice(a: std.mem.Allocator, items: []const []const u8) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |item| a.free(item);
        out.deinit();
    }
    for (items) |item| try out.append(try a.dupe(u8, item));
    return try out.toOwnedSlice();
}

fn freeStrSlice(a: std.mem.Allocator, items: []const []const u8) void {
    for (items) |item| a.free(item);
    a.free(items);
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
