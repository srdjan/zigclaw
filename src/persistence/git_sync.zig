const std = @import("std");
const config = @import("../config.zig");

pub const SyncError = error{
    GitDisabled,
    GitNotInstalled,
    RepoNotInitialized,
    RepoBusy,
    NoRemote,
    PushFailed,
    PathOutsideWorkspace,
    PathOutsideRepo,
    GitCommandFailed,
};

pub const StatusResult = struct {
    repo_ok: bool,
    remote_configured: bool,
    syncable_paths: [][]u8,
    ignored_paths: [][]u8,

    pub fn deinit(self: *StatusResult, a: std.mem.Allocator) void {
        for (self.syncable_paths) |p| a.free(p);
        a.free(self.syncable_paths);
        for (self.ignored_paths) |p| a.free(p);
        a.free(self.ignored_paths);
    }
};

pub const SyncOptions = struct {
    message: ?[]const u8 = null,
    push: bool = false,
};

pub const SyncResult = struct {
    noop: bool,
    committed: bool,
    pushed: bool,
    commit_hash: ?[]u8,
    syncable_count: usize,
    ignored_count: usize,

    pub fn deinit(self: *SyncResult, a: std.mem.Allocator) void {
        if (self.commit_hash) |h| a.free(h);
    }
};

pub const InitOptions = struct {
    remote: ?[]const u8 = null,
    branch: ?[]const u8 = null,
};

pub const InitResult = struct {
    repo_ready: bool,
    remote_configured: bool,
    branch: []u8,

    pub fn deinit(self: *InitResult, a: std.mem.Allocator) void {
        a.free(self.branch);
    }
};

const CmdResult = struct {
    exit_code: u8,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: *CmdResult, a: std.mem.Allocator) void {
        a.free(self.stdout);
        a.free(self.stderr);
    }
};

const RuntimePaths = struct {
    workspace_root: []u8,
    repo_dir: []u8,
    allow_repo_paths: [][]u8,
    deny_repo_paths: [][]u8,

    fn deinit(self: *RuntimePaths, a: std.mem.Allocator) void {
        a.free(self.workspace_root);
        a.free(self.repo_dir);
        for (self.allow_repo_paths) |p| a.free(p);
        a.free(self.allow_repo_paths);
        for (self.deny_repo_paths) |p| a.free(p);
        a.free(self.deny_repo_paths);
    }
};

pub fn status(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig) !StatusResult {
    try ensureGitEnabled(cfg);
    try ensureGitInstalled(a, io);

    var rp = try runtimePaths(a, cfg);
    defer rp.deinit(a);

    const repo_ok = isRepoReady(a, io, rp.repo_dir) catch false;
    if (!repo_ok) return .{ .repo_ok = false, .remote_configured = false, .syncable_paths = try a.dupe([]u8, &.{}), .ignored_paths = try a.dupe([]u8, &.{}) };

    var changes = try loadRepoChanges(a, io, rp);
    defer changes.deinit(a);

    const remote_ok = hasRemoteConfigured(a, io, rp.repo_dir, cfg.raw.persistence.git.remote_name) catch false;

    return .{
        .repo_ok = true,
        .remote_configured = remote_ok,
        .syncable_paths = try changes.syncable.toOwnedSlice(),
        .ignored_paths = try changes.ignored.toOwnedSlice(),
    };
}

pub fn statusJsonAlloc(a: std.mem.Allocator, s: StatusResult) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("repo_ok");
    try stream.write(s.repo_ok);
    try stream.objectField("remote_configured");
    try stream.write(s.remote_configured);
    try stream.objectField("syncable_paths");
    try stream.beginArray();
    for (s.syncable_paths) |p| try stream.write(p);
    try stream.endArray();
    try stream.objectField("ignored_paths");
    try stream.beginArray();
    for (s.ignored_paths) |p| try stream.write(p);
    try stream.endArray();
    try stream.endObject();

    return try aw.toOwnedSlice();
}

pub fn sync(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, opts: SyncOptions) !SyncResult {
    try ensureGitEnabled(cfg);
    try ensureGitInstalled(a, io);

    var rp = try runtimePaths(a, cfg);
    defer rp.deinit(a);

    if (!(try isRepoReady(a, io, rp.repo_dir))) return SyncError.RepoNotInitialized;

    if (try hasRepoBusyState(a, io, rp.repo_dir)) return SyncError.RepoBusy;

    var changes = try loadRepoChanges(a, io, rp);
    defer changes.deinit(a);

    if (changes.syncable.items.len == 0) {
        return .{
            .noop = true,
            .committed = false,
            .pushed = false,
            .commit_hash = null,
            .syncable_count = 0,
            .ignored_count = changes.ignored.items.len,
        };
    }

    try stagePaths(a, io, rp.repo_dir, changes.syncable.items);

    const staged = try stagedPathsCount(a, io, rp.repo_dir);
    if (staged == 0) {
        return .{
            .noop = true,
            .committed = false,
            .pushed = false,
            .commit_hash = null,
            .syncable_count = changes.syncable.items.len,
            .ignored_count = changes.ignored.items.len,
        };
    }

    const ts_ms = nowUnixMs(io);
    const msg = if (opts.message) |m|
        try a.dupe(u8, m)
    else
        try std.fmt.allocPrint(a, "zigclaw sync {d}", .{ts_ms});
    defer a.free(msg);

    try commitStaged(a, io, rp.repo_dir, cfg.raw.persistence.git.author_name, cfg.raw.persistence.git.author_email, msg);

    const hash = try currentHeadAlloc(a, io, rp.repo_dir);

    const should_push = opts.push or cfg.raw.persistence.git.push_default;
    var pushed = false;
    if (should_push) {
        if (!(try hasRemoteConfigured(a, io, rp.repo_dir, cfg.raw.persistence.git.remote_name))) return SyncError.NoRemote;

        pushHead(
            a,
            io,
            rp.repo_dir,
            cfg.raw.persistence.git.remote_name,
            cfg.raw.persistence.git.default_branch,
        ) catch return SyncError.PushFailed;
        pushed = true;
    }

    return .{
        .noop = false,
        .committed = true,
        .pushed = pushed,
        .commit_hash = hash,
        .syncable_count = changes.syncable.items.len,
        .ignored_count = changes.ignored.items.len,
    };
}

pub fn syncJsonAlloc(a: std.mem.Allocator, r: SyncResult) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("noop");
    try stream.write(r.noop);
    try stream.objectField("committed");
    try stream.write(r.committed);
    try stream.objectField("pushed");
    try stream.write(r.pushed);
    try stream.objectField("syncable_count");
    try stream.write(r.syncable_count);
    try stream.objectField("ignored_count");
    try stream.write(r.ignored_count);
    if (r.commit_hash) |h| {
        try stream.objectField("commit_hash");
        try stream.write(h);
    }
    try stream.endObject();

    return try aw.toOwnedSlice();
}

pub fn initRepo(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, opts: InitOptions) !InitResult {
    try ensureGitEnabled(cfg);
    try ensureGitInstalled(a, io);

    var rp = try runtimePaths(a, cfg);
    defer rp.deinit(a);

    try std.Io.Dir.cwd().createDirPath(io, rp.repo_dir);

    var repo_exists = isRepoReady(a, io, rp.repo_dir) catch false;
    if (!repo_exists) {
        var argv = std.array_list.Managed([]const u8).init(a);
        defer argv.deinit();
        try argv.appendSlice(&.{ "git", "-C", rp.repo_dir, "init" });
        try runGitOk(a, io, argv.items);
        repo_exists = true;
    }

    const branch = opts.branch orelse cfg.raw.persistence.git.default_branch;
    try checkoutBranch(a, io, rp.repo_dir, branch);

    if (opts.remote) |remote_url| {
        setRemote(
            a,
            io,
            rp.repo_dir,
            cfg.raw.persistence.git.remote_name,
            remote_url,
        ) catch return SyncError.GitCommandFailed;
    }

    try ensureGitIgnoreContainsDenyPaths(a, io, rp.repo_dir, rp.deny_repo_paths);

    const remote_ok = hasRemoteConfigured(a, io, rp.repo_dir, cfg.raw.persistence.git.remote_name) catch false;

    return .{
        .repo_ready = repo_exists,
        .remote_configured = remote_ok,
        .branch = try a.dupe(u8, branch),
    };
}

pub fn initJsonAlloc(a: std.mem.Allocator, r: InitResult) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("repo_ready");
    try stream.write(r.repo_ready);
    try stream.objectField("remote_configured");
    try stream.write(r.remote_configured);
    try stream.objectField("branch");
    try stream.write(r.branch);
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn ensureGitEnabled(cfg: config.ValidatedConfig) SyncError!void {
    if (!cfg.raw.persistence.git.enabled) return SyncError.GitDisabled;
}

fn runtimePaths(a: std.mem.Allocator, cfg: config.ValidatedConfig) !RuntimePaths {
    const workspace = try normalizePathAlloc(a, cfg.raw.security.workspace_root);
    errdefer a.free(workspace);

    const repo_raw = try resolveFromBaseAlloc(a, workspace, cfg.raw.persistence.git.repo_dir);
    errdefer a.free(repo_raw);

    if (!pathWithin(workspace, repo_raw)) return SyncError.PathOutsideWorkspace;

    var allow_repo = std.array_list.Managed([]u8).init(a);
    errdefer {
        for (allow_repo.items) |p| a.free(p);
        allow_repo.deinit();
    }

    for (cfg.raw.persistence.git.allow_paths) |p| {
        const abs = try resolveFromBaseAlloc(a, workspace, p);
        defer a.free(abs);
        if (!pathWithin(workspace, abs)) return SyncError.PathOutsideWorkspace;
        try allow_repo.append(try toRepoRelativeAlloc(a, repo_raw, abs));
    }

    var deny_repo = std.array_list.Managed([]u8).init(a);
    errdefer {
        for (deny_repo.items) |p| a.free(p);
        deny_repo.deinit();
    }

    for (cfg.raw.persistence.git.deny_paths) |p| {
        const abs = try resolveFromBaseAlloc(a, workspace, p);
        defer a.free(abs);
        if (!pathWithin(workspace, abs)) return SyncError.PathOutsideWorkspace;

        const rel = toRepoRelativeAlloc(a, repo_raw, abs) catch continue;
        try deny_repo.append(rel);
    }

    return .{
        .workspace_root = workspace,
        .repo_dir = repo_raw,
        .allow_repo_paths = try allow_repo.toOwnedSlice(),
        .deny_repo_paths = try deny_repo.toOwnedSlice(),
    };
}

fn resolveFromBaseAlloc(a: std.mem.Allocator, base: []const u8, path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(path)) return normalizePathAlloc(a, path);

    if (std.mem.eql(u8, base, ".")) return normalizePathAlloc(a, path);

    const joined = try std.fs.path.join(a, &.{ base, path });
    defer a.free(joined);
    return normalizePathAlloc(a, joined);
}

fn normalizePathAlloc(a: std.mem.Allocator, in_path: []const u8) ![]u8 {
    const is_abs = std.fs.path.isAbsolute(in_path);

    var parts = std.array_list.Managed([]const u8).init(a);
    defer parts.deinit();

    var it = std.mem.splitScalar(u8, in_path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (parts.items.len > 0 and !std.mem.eql(u8, parts.items[parts.items.len - 1], "..")) {
                _ = parts.pop();
            } else if (!is_abs) {
                try parts.append(seg);
            }
            continue;
        }
        try parts.append(seg);
    }

    if (parts.items.len == 0) {
        if (is_abs) return a.dupe(u8, "/");
        return a.dupe(u8, ".");
    }

    var len: usize = 0;
    if (is_abs) len += 1;
    for (parts.items, 0..) |seg, i| {
        if (i > 0) len += 1;
        len += seg.len;
    }

    const out = try a.alloc(u8, len);
    var i: usize = 0;
    if (is_abs) {
        out[i] = '/';
        i += 1;
    }
    for (parts.items, 0..) |seg, idx| {
        if (idx > 0) {
            out[i] = '/';
            i += 1;
        }
        @memcpy(out[i .. i + seg.len], seg);
        i += seg.len;
    }
    return out;
}

fn pathWithin(base: []const u8, path: []const u8) bool {
    if (std.mem.eql(u8, base, ".")) {
        if (std.fs.path.isAbsolute(path)) return false;
        if (std.mem.eql(u8, path, "..")) return false;
        return !std.mem.startsWith(u8, path, "../");
    }

    if (std.mem.eql(u8, base, "/")) return std.fs.path.isAbsolute(path);

    if (std.mem.eql(u8, base, path)) return true;
    if (!std.mem.startsWith(u8, path, base)) return false;
    if (path.len == base.len) return true;
    return path[base.len] == '/';
}

fn toRepoRelativeAlloc(a: std.mem.Allocator, repo_root: []const u8, abs_path: []const u8) ![]u8 {
    if (!pathWithin(repo_root, abs_path)) return SyncError.PathOutsideRepo;

    if (std.mem.eql(u8, repo_root, abs_path)) return a.dupe(u8, ".");

    if (std.mem.eql(u8, repo_root, ".")) return a.dupe(u8, abs_path);

    const offs = if (repo_root[repo_root.len - 1] == '/') repo_root.len else repo_root.len + 1;
    return a.dupe(u8, abs_path[offs..]);
}

fn ensureGitInstalled(a: std.mem.Allocator, io: std.Io) !void {
    var res = runCommand(a, io, &.{ "git", "--version" }) catch |e| switch (e) {
        error.FileNotFound => return SyncError.GitNotInstalled,
        else => return e,
    };
    defer res.deinit(a);
    if (res.exit_code != 0) return SyncError.GitNotInstalled;
}

fn isRepoReady(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8) !bool {
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{ "git", "-C", repo_dir, "rev-parse", "--show-cdup" });

    var res = runCommand(a, io, argv.items) catch |e| switch (e) {
        error.FileNotFound => return SyncError.GitNotInstalled,
        else => return e,
    };
    defer res.deinit(a);
    if (res.exit_code != 0) return false;

    // Empty output means repo_dir itself is the work tree root. Non-empty means
    // repo_dir is only a subdirectory within some parent repository.
    return std.mem.trim(u8, res.stdout, " \t\r\n").len == 0;
}

const ChangesResult = struct {
    syncable: std.array_list.Managed([]u8),
    ignored: std.array_list.Managed([]u8),

    fn deinit(self: *ChangesResult, a: std.mem.Allocator) void {
        for (self.syncable.items) |p| a.free(p);
        self.syncable.deinit();
        for (self.ignored.items) |p| a.free(p);
        self.ignored.deinit();
    }
};

fn loadRepoChanges(a: std.mem.Allocator, io: std.Io, rp: RuntimePaths) !ChangesResult {
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{
        "git", "-C", rp.repo_dir,
        "status", "--porcelain", "--untracked-files=all", "--ignored",
    });

    var res = try runCommand(a, io, argv.items);
    defer res.deinit(a);

    if (res.exit_code != 0) {
        if (std.mem.indexOf(u8, res.stderr, "not a git repository") != null) return SyncError.RepoNotInitialized;
        return SyncError.GitCommandFailed;
    }

    var syncable = std.array_list.Managed([]u8).init(a);
    errdefer {
        for (syncable.items) |p| a.free(p);
        syncable.deinit();
    }

    var ignored = std.array_list.Managed([]u8).init(a);
    errdefer {
        for (ignored.items) |p| a.free(p);
        ignored.deinit();
    }

    var lines = std.mem.splitScalar(u8, res.stdout, '\n');
    while (lines.next()) |line0| {
        const line = std.mem.trimEnd(u8, line0, "\r");
        if (line.len < 4) continue;

        const path_part0 = std.mem.trim(u8, line[3..], " \t");
        if (path_part0.len == 0) continue;

        const path_part = if (std.mem.indexOf(u8, path_part0, " -> ")) |idx|
            path_part0[idx + 4 ..]
        else
            path_part0;

        const path_clean = trimPorcelainPath(path_part);
        const norm = try normalizePathAlloc(a, path_clean);
        defer a.free(norm);

        const allowed = isPathAllowed(norm, rp.allow_repo_paths, rp.deny_repo_paths);
        if (allowed) {
            if (!containsPath(syncable.items, norm)) {
                try syncable.append(try a.dupe(u8, norm));
            }
        } else {
            if (!containsPath(ignored.items, norm)) {
                try ignored.append(try a.dupe(u8, norm));
            }
        }
    }

    std.sort.block([]u8, syncable.items, {}, struct {
        fn lt(_: void, a_: []u8, b_: []u8) bool {
            return std.mem.lessThan(u8, a_, b_);
        }
    }.lt);
    std.sort.block([]u8, ignored.items, {}, struct {
        fn lt(_: void, a_: []u8, b_: []u8) bool {
            return std.mem.lessThan(u8, a_, b_);
        }
    }.lt);

    return .{ .syncable = syncable, .ignored = ignored };
}

fn trimPorcelainPath(p: []const u8) []const u8 {
    const t = std.mem.trim(u8, p, " \t");
    if (t.len >= 2 and t[0] == '"' and t[t.len - 1] == '"') {
        return t[1 .. t.len - 1];
    }
    return t;
}

fn containsPath(paths: [][]u8, target: []const u8) bool {
    for (paths) |p| {
        if (std.mem.eql(u8, p, target)) return true;
    }
    return false;
}

fn isPathAllowed(path: []const u8, allow_paths: [][]u8, deny_paths: [][]u8) bool {
    var allow = false;
    for (allow_paths) |p| {
        if (pathWithin(p, path)) {
            allow = true;
            break;
        }
    }
    if (!allow) return false;

    for (deny_paths) |p| {
        if (pathWithin(p, path)) return false;
    }
    return true;
}

fn hasRemoteConfigured(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8, remote_name: []const u8) !bool {
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{ "git", "-C", repo_dir, "remote", "get-url", remote_name });

    var res = try runCommand(a, io, argv.items);
    defer res.deinit(a);
    return res.exit_code == 0;
}

fn stagePaths(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8, paths: [][]u8) !void {
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{ "git", "-C", repo_dir, "add", "-A", "--" });
    for (paths) |p| try argv.append(p);
    try runGitOk(a, io, argv.items);
}

fn stagedPathsCount(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8) !usize {
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{ "git", "-C", repo_dir, "status", "--porcelain" });

    var res = try runCommand(a, io, argv.items);
    defer res.deinit(a);
    if (res.exit_code != 0) return SyncError.GitCommandFailed;

    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, res.stdout, '\n');
    while (lines.next()) |ln| {
        const t = std.mem.trim(u8, ln, " \t\r");
        if (t.len < 2) continue;

        // Porcelain v1: first column is index status, second is working tree.
        // Count entries staged in index and ignore pure-untracked ("??") lines.
        if (t[0] != ' ' and t[0] != '?') count += 1;
    }
    return count;
}

fn commitStaged(
    a: std.mem.Allocator,
    io: std.Io,
    repo_dir: []const u8,
    author_name: []const u8,
    author_email: []const u8,
    message: []const u8,
) !void {
    const name_cfg = try std.fmt.allocPrint(a, "user.name={s}", .{author_name});
    defer a.free(name_cfg);
    const email_cfg = try std.fmt.allocPrint(a, "user.email={s}", .{author_email});
    defer a.free(email_cfg);

    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{
        "git", "-C", repo_dir,
        "-c", name_cfg,
        "-c", email_cfg,
        "commit", "-m", message,
    });
    try runGitOk(a, io, argv.items);
}

fn currentHeadAlloc(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8) ![]u8 {
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{ "git", "-C", repo_dir, "rev-parse", "HEAD" });

    var res = try runCommand(a, io, argv.items);
    defer res.deinit(a);
    if (res.exit_code != 0) return SyncError.GitCommandFailed;

    return a.dupe(u8, std.mem.trimEnd(u8, std.mem.trimEnd(u8, res.stdout, "\n"), "\r"));
}

fn pushHead(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8, remote_name: []const u8, branch: []const u8) !void {
    const refspec = try std.fmt.allocPrint(a, "HEAD:{s}", .{branch});
    defer a.free(refspec);

    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{ "git", "-C", repo_dir, "push", remote_name, refspec });

    var res = try runCommand(a, io, argv.items);
    defer res.deinit(a);
    if (res.exit_code != 0) return SyncError.PushFailed;
}

fn checkoutBranch(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8, branch: []const u8) !void {
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{ "git", "-C", repo_dir, "checkout", "-B", branch });
    try runGitOk(a, io, argv.items);
}

fn setRemote(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8, remote_name: []const u8, remote_url: []const u8) !void {
    if (try hasRemoteConfigured(a, io, repo_dir, remote_name)) {
        var setv = std.array_list.Managed([]const u8).init(a);
        defer setv.deinit();
        try setv.appendSlice(&.{ "git", "-C", repo_dir, "remote", "set-url", remote_name, remote_url });
        try runGitOk(a, io, setv.items);
        return;
    }

    var addv = std.array_list.Managed([]const u8).init(a);
    defer addv.deinit();
    try addv.appendSlice(&.{ "git", "-C", repo_dir, "remote", "add", remote_name, remote_url });
    try runGitOk(a, io, addv.items);
}

fn hasRepoBusyState(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8) !bool {
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();
    try argv.appendSlice(&.{ "git", "-C", repo_dir, "rev-parse", "-q", "--verify", "MERGE_HEAD" });

    var res = try runCommand(a, io, argv.items);
    defer res.deinit(a);
    return res.exit_code == 0;
}

fn ensureGitIgnoreContainsDenyPaths(a: std.mem.Allocator, io: std.Io, repo_dir: []const u8, deny_repo_paths: [][]u8) !void {
    const path = try std.fs.path.join(a, &.{ repo_dir, ".gitignore" });
    defer a.free(path);

    const existing = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(512 * 1024)) catch |e| switch (e) {
        error.FileNotFound => try a.dupe(u8, ""),
        else => return e,
    };
    defer a.free(existing);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    try aw.writer.writeAll(existing);
    var modified = false;

    for (deny_repo_paths) |entry| {
        const line = normalizeGitignoreEntry(entry);
        if (line.len == 0) continue;
        if (containsLine(existing, line)) continue;

        if (existing.len > 0 or modified) {
            if (!(existing.len > 0 and std.mem.endsWith(u8, existing, "\n") and !modified)) {
                try aw.writer.writeAll("\n");
            }
        }
        try aw.writer.writeAll(line);
        try aw.writer.writeAll("\n");
        modified = true;
    }

    if (!modified) return;

    const out = try aw.toOwnedSlice();
    defer a.free(out);

    var f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var w = f.writer(io, &buf);
    try w.interface.writeAll(out);
    try w.flush();
}

fn normalizeGitignoreEntry(entry: []const u8) []const u8 {
    var t = std.mem.trim(u8, entry, " \t");
    if (std.mem.eql(u8, t, ".")) return "";
    if (std.mem.startsWith(u8, t, "./")) t = t[2..];
    return t;
}

fn containsLine(content: []const u8, line: []const u8) bool {
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |ln| {
        if (std.mem.eql(u8, std.mem.trim(u8, ln, " \t\r"), line)) return true;
    }
    return false;
}

fn runGitOk(a: std.mem.Allocator, io: std.Io, argv: []const []const u8) !void {
    var res = runCommand(a, io, argv) catch |e| switch (e) {
        error.FileNotFound => return SyncError.GitNotInstalled,
        else => return e,
    };
    defer res.deinit(a);

    if (res.exit_code != 0) return SyncError.GitCommandFailed;
}

fn runCommand(a: std.mem.Allocator, io: std.Io, argv: []const []const u8) !CmdResult {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    var stdout_bytes: []u8 = &.{};
    errdefer if (stdout_bytes.len > 0) a.free(stdout_bytes);
    var stderr_bytes: []u8 = &.{};
    errdefer if (stderr_bytes.len > 0) a.free(stderr_bytes);

    if (child.stdout) |*out| {
        var obuf: [4096]u8 = undefined;
        var r = out.reader(io, &obuf);
        stdout_bytes = try r.interface.allocRemaining(a, std.Io.Limit.limited(1024 * 1024));
    } else {
        stdout_bytes = try a.dupe(u8, "");
    }

    if (child.stderr) |*errf| {
        var ebuf: [4096]u8 = undefined;
        var r2 = errf.reader(io, &ebuf);
        stderr_bytes = try r2.interface.allocRemaining(a, std.Io.Limit.limited(1024 * 1024));
    } else {
        stderr_bytes = try a.dupe(u8, "");
    }

    const term = try child.wait(io);
    const exit_code: u8 = switch (term) {
        .exited => |c| c,
        else => 1,
    };

    return .{
        .exit_code = exit_code,
        .stdout = stdout_bytes,
        .stderr = stderr_bytes,
    };
}

fn nowUnixMs(io: std.Io) i64 {
    const ts = std.Io.Clock.now(.real, io);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}
