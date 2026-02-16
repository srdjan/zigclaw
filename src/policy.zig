const std = @import("std");
const cfg = @import("config.zig");
const hash_mod = @import("obs/hash.zig");
const commands = @import("security/commands.zig");
const token_mod = @import("policy/token.zig");

pub const Mount = struct {
    host_path: []const u8,
    guest_path: []const u8,
    read_only: bool,
};

pub const Preset = struct {
    name: []const u8,
    tools: []const []const u8,
    allow_network: bool,
    allow_write_paths: []const []const u8,
};

pub const PolicyPlan = struct {
    active_preset: []const u8,
    workspace_root: []const u8,
    allow_network: bool,
    write_paths: []const []const u8,

    // derived allow-set (borrowed keys; Policy owns the strings)
    allowed_tools: std.StringHashMap(void),

    // stable hash hex (owned by Policy)
    policy_hash_hex: []const u8,

    pub fn deinit(self: *PolicyPlan) void {
        self.allowed_tools.deinit();
        // policy_hash_hex is owned by Policy (freed there)
    }

    pub fn isToolAllowed(self: *const PolicyPlan, tool: []const u8) bool {
        return self.allowed_tools.contains(tool);
    }
};

pub const Policy = struct {
    workspace_root: []const u8,
    active: Preset,
    presets: []Preset,

    plan: PolicyPlan,

    pub fn deinit(self: *Policy, a: std.mem.Allocator) void {
        self.plan.deinit();
        a.free(self.plan.policy_hash_hex);

        for (self.presets) |p| {
            a.free(p.name);
            for (p.tools) |t| a.free(t);
            a.free(p.tools);
            for (p.allow_write_paths) |w| a.free(w);
            a.free(p.allow_write_paths);
        }
        a.free(self.presets);
        a.free(self.workspace_root);
    }

    pub fn fromConfig(a: std.mem.Allocator, caps: cfg.CapabilitiesConfig, workspace_root: []const u8) !Policy {
        const ws = try a.dupe(u8, workspace_root);
        errdefer a.free(ws);

        var presets = std.array_list.Managed(Preset).init(a);
        errdefer {
            for (presets.items) |p| {
                a.free(p.name);
                for (p.tools) |t| a.free(t);
                a.free(p.tools);
                for (p.allow_write_paths) |w| a.free(w);
                a.free(p.allow_write_paths);
            }
            presets.deinit();
        }

        for (caps.presets) |p0| {
            const name = try a.dupe(u8, p0.name);
            const tools = try dupeStrSlice(a, p0.tools);
            const writes = try dupeStrSlice(a, p0.allow_write_paths);
            try presets.append(.{
                .name = name,
                .tools = tools,
                .allow_network = p0.allow_network,
                .allow_write_paths = writes,
            });
        }

        const presets_slice = try presets.toOwnedSlice();
        errdefer {
            for (presets_slice) |p| {
                a.free(p.name);
                for (p.tools) |t| a.free(t);
                a.free(p.tools);
                for (p.allow_write_paths) |w| a.free(w);
                a.free(p.allow_write_paths);
            }
            a.free(presets_slice);
        }

        const active_name = caps.active_preset;
        var active: ?Preset = null;
        for (presets_slice) |p| {
            if (std.mem.eql(u8, p.name, active_name)) {
                active = p;
                break;
            }
        }
        if (active == null) active = presets_slice[0];

        // compile plan
        var allowed_tools = std.StringHashMap(void).init(a);
        errdefer allowed_tools.deinit();
        for (active.?.tools) |t| {
            // keys are borrowed slices into Policy-owned strings
            try allowed_tools.put(t, {});
        }

        const hash_hex = try computePolicyHashHex(a, ws, active.?);

        const plan = PolicyPlan{
            .active_preset = active.?.name,
            .workspace_root = ws,
            .allow_network = active.?.allow_network,
            .write_paths = active.?.allow_write_paths,
            .allowed_tools = allowed_tools,
            .policy_hash_hex = hash_hex,
        };

        return .{
            .workspace_root = ws,
            .active = active.?,
            .presets = presets_slice,
            .plan = plan,
        };
    }

    pub fn isToolAllowed(self: Policy, tool: []const u8) bool {
        return self.plan.isToolAllowed(tool);
    }

    pub fn allowed_tools_count(self: Policy) usize {
        return self.active.tools.len;
    }

    pub fn presets_count(self: Policy) usize {
        return self.presets.len;
    }

    pub fn policyHash(self: Policy) []const u8 {
        return self.plan.policy_hash_hex;
    }

    pub fn attenuate(a: std.mem.Allocator, child: Policy, token: token_mod.CapabilityToken) !Policy {
        const ws = try a.dupe(u8, child.workspace_root);
        errdefer a.free(ws);

        const name = try std.fmt.allocPrint(a, "{s}+token", .{child.active.name});
        errdefer a.free(name);

        const tools = try intersectToolSlicesAlloc(a, child.active.tools, token.allowed_tools);
        errdefer freeStrSlice(a, tools);

        const write_paths = try intersectWritePathSlicesAlloc(a, child.active.allow_write_paths, token.write_paths);
        errdefer freeStrSlice(a, write_paths);

        const active = Preset{
            .name = name,
            .tools = tools,
            .allow_network = child.active.allow_network and token.allow_network,
            .allow_write_paths = write_paths,
        };

        const presets = try a.alloc(Preset, 1);
        presets[0] = active;
        errdefer {
            a.free(active.name);
            freeStrSlice(a, active.tools);
            freeStrSlice(a, active.allow_write_paths);
            a.free(presets);
        }

        var allowed_tools = std.StringHashMap(void).init(a);
        errdefer allowed_tools.deinit();
        for (active.tools) |tool| {
            try allowed_tools.put(tool, {});
        }

        const hash_hex = try computePolicyHashHex(a, ws, active);

        const plan = PolicyPlan{
            .active_preset = active.name,
            .workspace_root = ws,
            .allow_network = active.allow_network,
            .write_paths = active.allow_write_paths,
            .allowed_tools = allowed_tools,
            .policy_hash_hex = hash_hex,
        };

        return .{
            .workspace_root = ws,
            .active = active,
            .presets = presets,
            .plan = plan,
        };
    }

    pub fn explainToolJsonAlloc(self: Policy, a: std.mem.Allocator, tool: []const u8) ![]u8 {
        const allowed = self.isToolAllowed(tool);
        const reason = if (allowed)
            try std.fmt.allocPrint(a, "allowed by preset '{s}'", .{self.active.name})
        else
            try std.fmt.allocPrint(a, "denied: tool not in preset '{s}'", .{self.active.name});
        defer a.free(reason);

        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();

        var stream: std.json.Stringify = .{ .writer = &aw.writer };

        try stream.beginObject();
        try stream.objectField("tool");
        try stream.write(tool);
        try stream.objectField("allowed");
        try stream.write(allowed);
        try stream.objectField("reason");
        try stream.write(reason);
        try stream.objectField("policy_hash");
        try stream.write(self.policyHash());
        try stream.endObject();

        return try aw.toOwnedSlice();
    }

    pub fn explainMountJsonAlloc(self: Policy, a: std.mem.Allocator, host_path: []const u8) ![]u8 {
        const explain = try self.explainMountAlloc(a, host_path);
        defer explain.deinit(a);

        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        var stream: std.json.Stringify = .{ .writer = &aw.writer };

        try stream.beginObject();
        try stream.objectField("mount");
        try stream.write(host_path);
        try stream.objectField("allowed");
        try stream.write(explain.allowed);
        try stream.objectField("reason");
        try stream.write(explain.reason);
        try stream.objectField("policy_hash");
        try stream.write(self.policyHash());
        if (explain.allowed) {
            try stream.objectField("guest_path");
            try stream.write(explain.guest_path.?);
            try stream.objectField("read_only");
            try stream.write(explain.read_only.?);
        }
        try stream.endObject();
        return try aw.toOwnedSlice();
    }

    pub fn explainCommandJsonAlloc(self: Policy, a: std.mem.Allocator, cmd: []const u8) ![]u8 {
        const allowed = commands.isCommandSafe(cmd);
        const reason = if (allowed)
            "allowed: command matches safe allowlist"
        else
            "denied: command contains unsafe bytes";

        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        var stream: std.json.Stringify = .{ .writer = &aw.writer };

        try stream.beginObject();
        try stream.objectField("command");
        try stream.write(cmd);
        try stream.objectField("allowed");
        try stream.write(allowed);
        try stream.objectField("reason");
        try stream.write(reason);
        try stream.objectField("policy_hash");
        try stream.write(self.policyHash());
        try stream.endObject();
        return try aw.toOwnedSlice();
    }

    pub fn makeMounts(self: Policy, a: std.mem.Allocator) ![]Mount {
        // Always mount workspace as read-only at /workspace
        var mounts = std.array_list.Managed(Mount).init(a);
        errdefer mounts.deinit();

        try mounts.append(.{ .host_path = self.workspace_root, .guest_path = "/workspace", .read_only = true });

        for (self.active.allow_write_paths) |p| {
            // mount each writable path at /write/<basename>
            const base = basename(p);
            const guest = try std.fmt.allocPrint(a, "/write/{s}", .{base});
            try mounts.append(.{ .host_path = p, .guest_path = guest, .read_only = false });
        }

        return try mounts.toOwnedSlice();
    }

    const MountExplain = struct {
        allowed: bool = false,
        read_only: ?bool = null,
        guest_path: ?[]u8 = null,
        reason: []u8,

        fn deinit(self: MountExplain, a: std.mem.Allocator) void {
            if (self.guest_path) |p| a.free(p);
            a.free(self.reason);
        }
    };

    fn explainMountAlloc(self: Policy, a: std.mem.Allocator, host_path: []const u8) !MountExplain {
        if (host_path.len == 0) {
            return .{
                .reason = try a.dupe(u8, "denied: empty mount path"),
            };
        }

        for (self.active.allow_write_paths) |wp| {
            if (pathWithin(host_path, wp)) {
                const base = basename(wp);
                const guest_root = try std.fmt.allocPrint(a, "/write/{s}", .{base});
                defer a.free(guest_root);
                return .{
                    .allowed = true,
                    .read_only = false,
                    .guest_path = try mapGuestPathAlloc(a, host_path, wp, guest_root),
                    .reason = try std.fmt.allocPrint(a, "allowed writable by preset '{s}' path '{s}'", .{ self.active.name, wp }),
                };
            }
        }

        if (pathWithin(host_path, self.workspace_root)) {
            return .{
                .allowed = true,
                .read_only = true,
                .guest_path = try mapGuestPathAlloc(a, host_path, self.workspace_root, "/workspace"),
                .reason = try std.fmt.allocPrint(a, "allowed read-only under workspace_root '{s}'", .{self.workspace_root}),
            };
        }

        return .{
            .reason = try std.fmt.allocPrint(a, "denied: path is outside workspace_root '{s}' and preset writable paths", .{self.workspace_root}),
        };
    }
};

fn dupeStrSlice(a: std.mem.Allocator, items: []const []const u8) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |s| a.free(s);
        out.deinit();
    }
    for (items) |s| try out.append(try a.dupe(u8, s));
    return try out.toOwnedSlice();
}

fn intersectToolSlicesAlloc(
    a: std.mem.Allocator,
    child_tools: []const []const u8,
    token_tools: []const []const u8,
) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |tool| a.free(tool);
        out.deinit();
    }

    for (child_tools) |tool| {
        if (!containsStr(token_tools, tool)) continue;
        if (containsStr(out.items, tool)) continue;
        try out.append(try a.dupe(u8, tool));
    }
    return try out.toOwnedSlice();
}

fn intersectWritePathSlicesAlloc(
    a: std.mem.Allocator,
    child_paths: []const []const u8,
    token_paths: []const []const u8,
) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |path| a.free(path);
        out.deinit();
    }

    for (child_paths) |child_path| {
        for (token_paths) |token_path| {
            const narrowed = narrowPathIntersection(child_path, token_path) orelse continue;
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

fn basename(path: []const u8) []const u8 {
    var i = path.len;
    while (i > 0) : (i -= 1) {
        const c = path[i - 1];
        if (c == '/' or c == '\\') return path[i..];
    }
    return path;
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

fn pathWithin(path: []const u8, root: []const u8) bool {
    const p = normalizePathForCompare(path);
    const r = normalizePathForCompare(root);

    // Relative workspace root ("."): allow any non-parent-escape relative path.
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

fn mapGuestPathAlloc(a: std.mem.Allocator, host_path: []const u8, host_root: []const u8, guest_root: []const u8) ![]u8 {
    const p = normalizePathForCompare(host_path);
    const r = normalizePathForCompare(host_root);

    if (r.len == 0 or std.mem.eql(u8, r, ".")) {
        if (p.len == 0 or std.mem.eql(u8, p, ".")) return try a.dupe(u8, guest_root);
        return try std.fmt.allocPrint(a, "{s}/{s}", .{ guest_root, p });
    }

    if (r.len == 1 and r[0] == '/') {
        if (std.mem.eql(u8, p, "/")) return try a.dupe(u8, guest_root);
        return try std.fmt.allocPrint(a, "{s}{s}", .{ guest_root, p });
    }

    if (std.mem.eql(u8, p, r)) return try a.dupe(u8, guest_root);
    if (p.len > r.len and std.mem.startsWith(u8, p, r) and p[r.len] == '/') {
        return try std.fmt.allocPrint(a, "{s}{s}", .{ guest_root, p[r.len..] });
    }
    return try a.dupe(u8, guest_root);
}

// ---- policy hash (sha256 hex) ----

fn computePolicyHashHex(a: std.mem.Allocator, workspace_root: []const u8, active: Preset) ![]const u8 {
    // canonicalize: preset name + sorted tools + sorted write paths + workspace root
    const tools_idxs = try a.alloc(usize, active.tools.len);
    defer a.free(tools_idxs);
    for (tools_idxs, 0..) |*p, i| p.* = i;
    std.sort.block(usize, tools_idxs, active.tools, struct {
        fn lessThan(tools: []const []const u8, ai: usize, bi: usize) bool {
            return std.mem.lessThan(u8, tools[ai], tools[bi]);
        }
    }.lessThan);

    const write_idxs = try a.alloc(usize, active.allow_write_paths.len);
    defer a.free(write_idxs);
    for (write_idxs, 0..) |*p, i| p.* = i;
    std.sort.block(usize, write_idxs, active.allow_write_paths, struct {
        fn lessThan(paths: []const []const u8, ai: usize, bi: usize) bool {
            return std.mem.lessThan(u8, paths[ai], paths[bi]);
        }
    }.lessThan);

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("workspace_root=");
    h.update(workspace_root);
    h.update(";preset=");
    h.update(active.name);
    h.update(";allow_network=");
    h.update(if (active.allow_network) "true" else "false");
    h.update(";tools=");
    for (tools_idxs) |i| {
        h.update(active.tools[i]);
        h.update(",");
    }
    h.update(";write_paths=");
    for (write_idxs) |i| {
        h.update(active.allow_write_paths[i]);
        h.update(",");
    }

    var digest: [32]u8 = undefined;
    h.final(&digest);
    return hash_mod.hexAlloc(a, &digest);
}
