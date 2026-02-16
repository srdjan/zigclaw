const std = @import("std");
const hash_mod = @import("../obs/hash.zig");
const policy_mod = @import("../policy.zig");
const workspace_mod = @import("../agent/workspace.zig");

pub const CachedResult = struct {
    ok: bool,
    data_json: []const u8,
    stdout: []const u8,
    stderr: []const u8,

    fn deinit(self: *CachedResult, a: std.mem.Allocator) void {
        a.free(self.data_json);
        a.free(self.stdout);
        a.free(self.stderr);
    }
};

pub const StoreInput = struct {
    ok: bool,
    data_json: []const u8,
    stdout: []const u8,
    stderr: []const u8,
};

pub const ToolCache = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace_root: []const u8,
    entries: std.StringHashMap(CachedResult),
    workspace_snapshot: ?workspace_mod.WorkspaceSnapshot = null,

    pub fn init(a: std.mem.Allocator, io: std.Io, workspace_root: []const u8) ToolCache {
        return .{
            .allocator = a,
            .io = io,
            .workspace_root = workspace_root,
            .entries = std.StringHashMap(CachedResult).init(a),
            .workspace_snapshot = null,
        };
    }

    pub fn deinit(self: *ToolCache) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var val = entry.value_ptr.*;
            val.deinit(self.allocator);
        }
        self.entries.deinit();
        self.invalidateWorkspaceSnapshot();
    }

    pub fn computeKey(
        self: *ToolCache,
        a: std.mem.Allocator,
        tool_name: []const u8,
        args_json: []const u8,
        mounts: []const policy_mod.Mount,
    ) ![]u8 {
        const snapshot = try self.ensureSnapshot();

        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("tool=");
        h.update(tool_name);
        h.update(";args=");
        h.update(args_json);
        h.update(";mounts=");

        for (mounts) |mount| {
            h.update("[host=");
            h.update(mount.host_path);
            h.update(";guest=");
            h.update(mount.guest_path);
            h.update(";read_only=");
            h.update(if (mount.read_only) "true" else "false");
            h.update(";content_hash=");
            try updateMountContentHash(self, &h, snapshot, mount.host_path);
            h.update("]");
        }

        var digest: [32]u8 = undefined;
        h.final(&digest);
        return hash_mod.hexAlloc(a, &digest);
    }

    pub fn lookup(self: *ToolCache, key: []const u8) ?*const CachedResult {
        return self.entries.getPtr(key);
    }

    pub fn store(self: *ToolCache, key: []const u8, value: StoreInput) !void {
        const key_dup = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_dup);

        var val = CachedResult{
            .ok = value.ok,
            .data_json = try self.allocator.dupe(u8, value.data_json),
            .stdout = try self.allocator.dupe(u8, value.stdout),
            .stderr = try self.allocator.dupe(u8, value.stderr),
        };
        errdefer val.deinit(self.allocator);

        const gop = try self.entries.getOrPut(key_dup);
        if (gop.found_existing) {
            // Keep original map key, replace value payload.
            self.allocator.free(key_dup);
            var old = gop.value_ptr.*;
            old.deinit(self.allocator);
            gop.value_ptr.* = val;
        } else {
            gop.key_ptr.* = key_dup;
            gop.value_ptr.* = val;
        }
    }

    pub fn invalidateWorkspaceSnapshot(self: *ToolCache) void {
        if (self.workspace_snapshot) |*snap| {
            snap.deinit(self.allocator);
            self.workspace_snapshot = null;
        }
    }

    fn ensureSnapshot(self: *ToolCache) !*const workspace_mod.WorkspaceSnapshot {
        if (self.workspace_snapshot == null) {
            self.workspace_snapshot = try workspace_mod.scan(
                self.allocator,
                self.io,
                self.workspace_root,
                .{},
            );
        }
        return &(self.workspace_snapshot.?);
    }
};

fn updateMountContentHash(
    self: *ToolCache,
    h: *std.crypto.hash.sha2.Sha256,
    snapshot: *const workspace_mod.WorkspaceSnapshot,
    mount_host_path: []const u8,
) !void {
    const rel_scope = mapHostPathToSnapshotScope(self.workspace_root, mount_host_path) orelse {
        // Fallback: if scope cannot be mapped into workspace snapshot, make key stable on host path.
        h.update("unmapped:");
        h.update(mount_host_path);
        return;
    };

    var matched_any = false;
    for (snapshot.files) |f| {
        if (!pathWithin(f.rel_path, rel_scope)) continue;
        matched_any = true;
        h.update(f.rel_path);
        h.update("=");
        h.update(f.sha256_hex);
        h.update(";");
    }
    if (!matched_any) h.update("<empty>");
}

fn mapHostPathToSnapshotScope(workspace_root: []const u8, host_path: []const u8) ?[]const u8 {
    const wr = normalizePathForCompare(workspace_root);
    const hp = normalizePathForCompare(host_path);

    // Common case: relative workspace root.
    if (wr.len == 0 or std.mem.eql(u8, wr, ".")) {
        if (hp.len == 0 or std.mem.eql(u8, hp, ".")) return ".";
        if (std.mem.startsWith(u8, hp, "/")) return null;
        if (isParentEscape(hp)) return null;
        return hp;
    }

    // Absolute/explicit workspace root.
    if (std.mem.eql(u8, hp, wr)) return ".";
    if (hp.len > wr.len and std.mem.startsWith(u8, hp, wr) and hp[wr.len] == '/') {
        return hp[wr.len + 1 ..];
    }
    return null;
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
