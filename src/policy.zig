const std = @import("std");
const cfg = @import("config.zig");

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

    // derived allow-set (borrowed keys; Policy owns the strings)
    allowed_tools: std.StringHashMap(void),

    // stable hash hex (owned by Policy)
    policy_hash_hex: []const u8,

    pub fn deinit(self: *PolicyPlan) void {
        self.allowed_tools.deinit();
        // policy_hash_hex is owned by Policy (freed there)
        _ = self;
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

        var presets = std.ArrayList(Preset).init(a);
        errdefer {
            for (presets.items) |p| {
                a.free(p.name);
                for (p.tools) |t| a.free(t);
                a.free(p.tools);
                for (p.allow_write_paths) |w| a.free(w);
                a.free(p.allow_write_paths);
            }
            presets.deinit();
            a.free(ws);
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

        const active_name = caps.active_preset;
        var active: ?Preset = null;
        for (presets_slice) |p| {
            if (std.mem.eql(u8, p.name, active_name)) { active = p; break; }
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

    pub fn explainToolJsonAlloc(self: Policy, a: std.mem.Allocator, tool: []const u8) ![]u8 {
        const allowed = self.isToolAllowed(tool);
        const reason = if (allowed)
            try std.fmt.allocPrint(a, "allowed by preset '{s}'", .{self.active.name})
        else
            try std.fmt.allocPrint(a, "denied: tool not in preset '{s}'", .{self.active.name});
        defer a.free(reason);

        var stream = std.json.StringifyStream.init(a);
        defer stream.deinit();

        try stream.beginObject();
        try stream.objectField("tool"); try stream.write(tool);
        try stream.objectField("allowed"); try stream.write(allowed);
        try stream.objectField("reason"); try stream.write(reason);
        try stream.objectField("policy_hash"); try stream.write(self.policyHash());
        try stream.endObject();

        return try stream.toOwnedSlice();
    }

    pub fn makeMounts(self: Policy, a: std.mem.Allocator) ![]Mount {
        // Always mount workspace as read-only at /workspace
        var mounts = std.ArrayList(Mount).init(a);
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
};

fn dupeStrSlice(a: std.mem.Allocator, items: []const []const u8) ![]const []const u8 {
    var out = std.ArrayList([]const u8).init(a);
    errdefer {
        for (out.items) |s| a.free(s);
        out.deinit();
    }
    for (items) |s| try out.append(try a.dupe(u8, s));
    return try out.toOwnedSlice();
}

fn basename(path: []const u8) []const u8 {
    var i = path.len;
    while (i > 0) : (i -= 1) {
        const c = path[i - 1];
        if (c == '/' or c == '\\') return path[i..];
    }
    return path;
}

// ---- policy hash (sha256 hex) ----

fn computePolicyHashHex(a: std.mem.Allocator, workspace_root: []const u8, active: Preset) ![]const u8 {
    // canonicalize: preset name + sorted tools + sorted write paths + workspace root
    var tools_idxs = try a.alloc(usize, active.tools.len);
    defer a.free(tools_idxs);
    for (tools_idxs, 0..) |*p, i| p.* = i;
    std.sort.block(usize, tools_idxs, active.tools, struct {
        fn lessThan(tools: []const []const u8, ai: usize, bi: usize) bool {
            return std.mem.lessThan(u8, tools[ai], tools[bi]);
        }
    }.lessThan);

    var write_idxs = try a.alloc(usize, active.allow_write_paths.len);
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

    // hex
    var out = try a.alloc(u8, 64);
    const hex = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i*2] = hex[(b >> 4) & 0xF];
        out[i*2 + 1] = hex[b & 0xF];
    }
    return out;
}
