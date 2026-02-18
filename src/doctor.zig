const std = @import("std");
const config_mod = @import("config.zig");
const manifest_mod = @import("tools/manifest.zig");

const Level = enum { ok, warn, fail };

const Check = struct {
    id: []const u8,
    level: Level,
    message: []const u8,
    hint: ?[]const u8 = null,
};

const Report = struct {
    checks: []Check,
    ok_count: usize,
    warn_count: usize,
    fail_count: usize,

    fn deinit(self: *Report, a: std.mem.Allocator) void {
        for (self.checks) |c| {
            a.free(c.id);
            a.free(c.message);
            if (c.hint) |h| a.free(h);
        }
        a.free(self.checks);
    }
};

const CheckList = std.array_list.Managed(Check);

pub fn run(a: std.mem.Allocator, io: std.Io, cfg_path: []const u8, as_json: bool) !void {
    var report = try buildReport(a, io, cfg_path);
    defer report.deinit(a);

    if (as_json) {
        try printJson(a, io, cfg_path, report);
    } else {
        try printText(io, cfg_path, report);
    }
}

fn buildReport(a: std.mem.Allocator, io: std.Io, cfg_path: []const u8) !Report {
    var checks = CheckList.init(a);
    errdefer {
        freeChecks(a, checks.items);
        checks.deinit();
    }

    var cfg_loaded = false;
    var cfg: config_mod.ValidatedConfig = undefined;
    if (config_mod.loadAndValidate(a, io, cfg_path)) |validated| {
        cfg_loaded = true;
        cfg = validated;
        const msg = try std.fmt.allocPrint(a, "loaded and validated '{s}'", .{cfg_path});
        try addCheck(a, &checks, .ok, "config.load", msg, null);

        if (validated.warnings.len > 0) {
            const warn_msg = try std.fmt.allocPrint(a, "{d} config warning(s)", .{validated.warnings.len});
            const hint = try std.fmt.allocPrint(a, "run: zigclaw config validate --config {s}", .{cfg_path});
            try addCheck(a, &checks, .warn, "config.warnings", warn_msg, hint);
        } else {
            const clean_msg = try a.dupe(u8, "no config warnings");
            try addCheck(a, &checks, .ok, "config.warnings", clean_msg, null);
        }
    } else |e| {
        const msg = try std.fmt.allocPrint(a, "failed to load config '{s}' ({s})", .{ cfg_path, @errorName(e) });
        const hint = try std.fmt.allocPrint(a, "run: zigclaw config validate --config {s}", .{cfg_path});
        try addCheck(a, &checks, .fail, "config.load", msg, hint);
    }
    defer if (cfg_loaded) cfg.deinit(a);

    // Dependency checks.
    const has_git = try commandInPath(a, io, "git");
    const has_curl = try commandInPath(a, io, "curl");
    const has_wasmtime = try commandInPath(a, io, "wasmtime");

    const git_required = cfg_loaded and cfg.raw.persistence.git.enabled;
    if (has_git) {
        const msg = if (git_required)
            try a.dupe(u8, "git found in PATH (required by persistence.git.enabled=true)")
        else
            try a.dupe(u8, "git found in PATH");
        try addCheck(a, &checks, .ok, "dependency.git", msg, null);
    } else {
        const level: Level = if (git_required) .fail else .warn;
        const msg = if (git_required)
            try a.dupe(u8, "git not found in PATH but persistence.git is enabled")
        else
            try a.dupe(u8, "git not found in PATH");
        const hint = try a.dupe(u8, "install git or disable [persistence.git].enabled");
        try addCheck(a, &checks, level, "dependency.git", msg, hint);
    }

    var manifest_count: usize = 0;
    var manifest_invalid: usize = 0;
    var wasi_manifest_count: usize = 0;
    var first_manifest_error: ?[]u8 = null;
    defer if (first_manifest_error) |s| a.free(s);

    if (cfg_loaded) {
        var dir = std.Io.Dir.cwd().openDir(io, cfg.raw.tools.plugin_dir, .{}) catch |e| {
            const msg = try std.fmt.allocPrint(a, "plugin_dir not accessible: {s} ({s})", .{ cfg.raw.tools.plugin_dir, @errorName(e) });
            const hint = try a.dupe(u8, "build plugins with: zig build plugins");
            try addCheck(a, &checks, .fail, "tools.plugin_dir", msg, hint);
            return finalizeReport(&checks);
        };
        defer dir.close(io);

        const dir_msg = try std.fmt.allocPrint(a, "plugin_dir is readable: {s}", .{cfg.raw.tools.plugin_dir});
        try addCheck(a, &checks, .ok, "tools.plugin_dir", dir_msg, null);

        var it = dir.iterate();
        while (try it.next(io)) |ent| {
            if (ent.kind != .file) continue;
            if (!std.mem.endsWith(u8, ent.name, ".toml")) continue;
            manifest_count += 1;

            const p = try std.fs.path.join(a, &.{ cfg.raw.tools.plugin_dir, ent.name });
            defer a.free(p);

            if (manifest_mod.loadManifest(a, io, p)) |owned| {
                if (!owned.manifest.native) wasi_manifest_count += 1;
                var tmp = owned;
                tmp.deinit(a);
            } else |e| {
                manifest_invalid += 1;
                if (first_manifest_error == null) {
                    first_manifest_error = try std.fmt.allocPrint(a, "{s}: {s}", .{ ent.name, @errorName(e) });
                }
            }
        }

        if (manifest_count == 0) {
            const msg = try a.dupe(u8, "no tool manifests found in plugin_dir");
            const hint = try a.dupe(u8, "build plugins with: zig build plugins");
            try addCheck(a, &checks, .warn, "tools.manifests", msg, hint);
        } else if (manifest_invalid > 0) {
            const msg = try std.fmt.allocPrint(a, "{d}/{d} manifests failed to parse (first: {s})", .{
                manifest_invalid,
                manifest_count,
                first_manifest_error orelse "unknown",
            });
            const hint = try a.dupe(u8, "inspect tool manifest TOML files in plugin_dir");
            try addCheck(a, &checks, .fail, "tools.manifests", msg, hint);
        } else {
            const msg = try std.fmt.allocPrint(a, "{d} manifest(s) parsed successfully", .{manifest_count});
            try addCheck(a, &checks, .ok, "tools.manifests", msg, null);
        }
    } else {
        const msg = try a.dupe(u8, "skipped plugin_dir/manifests check (config unavailable)");
        try addCheck(a, &checks, .warn, "tools.manifests", msg, null);
    }

    // wasmtime is required only when at least one manifest is WASI.
    const wasmtime_required = cfg_loaded and wasi_manifest_count > 0;
    if (has_wasmtime) {
        const msg = if (wasmtime_required)
            try std.fmt.allocPrint(a, "wasmtime found in PATH (required by {d} WASI manifest(s))", .{wasi_manifest_count})
        else
            try a.dupe(u8, "wasmtime found in PATH");
        try addCheck(a, &checks, .ok, "dependency.wasmtime", msg, null);
    } else {
        const level: Level = if (wasmtime_required) .fail else .warn;
        const msg = if (wasmtime_required)
            try std.fmt.allocPrint(a, "wasmtime not found in PATH but {d} manifest(s) require WASI runtime", .{wasi_manifest_count})
        else
            try a.dupe(u8, "wasmtime not found in PATH");
        const hint = try a.dupe(u8, "install wasmtime or use only native tool manifests");
        try addCheck(a, &checks, level, "dependency.wasmtime", msg, hint);
    }

    // Provider + curl + network gate checks.
    if (cfg_loaded) {
        const preset = activePreset(cfg.raw);
        const network_allowed = preset.allow_network;
        const provider_kind = cfg.raw.provider_primary.kind;

        if (provider_kind == .openai_compat and !network_allowed) {
            const msg = try std.fmt.allocPrint(a, "provider is openai_compat but active preset '{s}' has allow_network=false", .{
                preset.name,
            });
            const hint = try a.dupe(u8, "switch to a preset with allow_network=true or use providers.primary.kind=\"stub\"");
            try addCheck(a, &checks, .fail, "provider.network_gate", msg, hint);
        } else {
            const msg = try a.dupe(u8, "provider network gate is consistent with active preset");
            try addCheck(a, &checks, .ok, "provider.network_gate", msg, null);
        }

        const curl_required = provider_kind == .openai_compat;
        if (has_curl) {
            const msg = if (curl_required)
                try a.dupe(u8, "curl found in PATH (required by openai_compat provider)")
            else
                try a.dupe(u8, "curl found in PATH");
            try addCheck(a, &checks, .ok, "dependency.curl", msg, null);
        } else {
            const level: Level = if (curl_required) .fail else .warn;
            const msg = if (curl_required)
                try a.dupe(u8, "curl not found in PATH but provider kind is openai_compat")
            else
                try a.dupe(u8, "curl not found in PATH");
            const hint = try a.dupe(u8, "install curl or use providers.primary.kind=\"stub\"");
            try addCheck(a, &checks, level, "dependency.curl", msg, hint);
        }

        switch (provider_kind) {
            .stub => {
                const msg = try a.dupe(u8, "provider auth not required for stub");
                try addCheck(a, &checks, .ok, "provider.auth", msg, null);
            },
            .openai_compat => {
                if (cfg.raw.provider_primary.api_key.len > 0) {
                    const msg = try a.dupe(u8, "provider auth configured via inline api_key");
                    try addCheck(a, &checks, .ok, "provider.auth", msg, null);
                } else if (cfg.raw.provider_primary.api_key_vault.len > 0) {
                    if (std.Io.Dir.cwd().statFile(io, cfg.raw.vault_path, .{})) |_| {
                        const msg = try std.fmt.allocPrint(a, "provider auth configured via vault key '{s}'", .{
                            cfg.raw.provider_primary.api_key_vault,
                        });
                        const hint = try std.fmt.allocPrint(a, "verify with: zigclaw vault get {s} --vault {s}", .{
                            cfg.raw.provider_primary.api_key_vault,
                            cfg.raw.vault_path,
                        });
                        try addCheck(a, &checks, .warn, "provider.auth", msg, hint);
                    } else |_| {
                        const msg = try std.fmt.allocPrint(a, "vault file not found: {s}", .{cfg.raw.vault_path});
                        const hint = try std.fmt.allocPrint(a, "set secret with: zigclaw vault set {s} --vault {s}", .{
                            cfg.raw.provider_primary.api_key_vault,
                            cfg.raw.vault_path,
                        });
                        try addCheck(a, &checks, .fail, "provider.auth", msg, hint);
                    }
                } else {
                    const env_name = cfg.raw.provider_primary.api_key_env;
                    const env_name_z = try a.dupeZ(u8, env_name);
                    defer a.free(env_name_z);
                    const env_v = std.c.getenv(env_name_z);
                    if (env_v != null and std.mem.span(env_v.?).len > 0) {
                        const msg = try std.fmt.allocPrint(a, "provider auth env var is set: {s}", .{env_name});
                        try addCheck(a, &checks, .ok, "provider.auth", msg, null);
                    } else {
                        const msg = try std.fmt.allocPrint(a, "provider auth env var is not set: {s}", .{env_name});
                        const hint = try std.fmt.allocPrint(a, "export {s}=... or configure api_key_vault", .{env_name});
                        try addCheck(a, &checks, .fail, "provider.auth", msg, hint);
                    }
                }
            },
        }

        try checkWritablePaths(a, io, cfg, &checks);
    } else {
        if (has_curl) {
            const msg = try a.dupe(u8, "curl found in PATH");
            try addCheck(a, &checks, .ok, "dependency.curl", msg, null);
        } else {
            const msg = try a.dupe(u8, "curl not found in PATH");
            const hint = try a.dupe(u8, "install curl for update/openai_compat/http_fetch support");
            try addCheck(a, &checks, .warn, "dependency.curl", msg, hint);
        }
    }

    return finalizeReport(&checks);
}

fn checkWritablePaths(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config_mod.ValidatedConfig,
    checks: *CheckList,
) !void {
    var paths = std.array_list.Managed([]const u8).init(a);
    defer paths.deinit();

    try appendUniquePath(&paths, cfg.raw.logging.dir);
    try appendUniquePath(&paths, cfg.raw.observability.dir);
    try appendUniquePath(&paths, cfg.raw.queue.dir);
    try appendUniquePath(&paths, cfg.raw.memory.root);

    if (cfg.raw.gateway.rate_limit_enabled and cfg.raw.gateway.rate_limit_store == .file) {
        try appendUniquePath(&paths, cfg.raw.gateway.rate_limit_dir);
    }

    const preset = activePreset(cfg.raw);
    for (preset.allow_write_paths) |p| try appendUniquePath(&paths, p);

    if (paths.items.len == 0) {
        const msg = try a.dupe(u8, "no writable paths configured");
        try addCheck(a, checks, .warn, "paths.writable", msg, null);
        return;
    }

    for (paths.items) |p| {
        const full = try resolvePathAlloc(a, cfg.raw.security.workspace_root, p);
        defer a.free(full);

        std.Io.Dir.cwd().createDirPath(io, full) catch |e| {
            const msg = try std.fmt.allocPrint(a, "cannot create/access '{s}' ({s})", .{ full, @errorName(e) });
            const hint = try a.dupe(u8, "fix permissions or adjust workspace_root/allow_write_paths");
            try addCheck(a, checks, .fail, "paths.writable", msg, hint);
            continue;
        };

        const probe = try std.fs.path.join(a, &.{ full, ".zigclaw_doctor_probe.tmp" });
        defer a.free(probe);

        var f = std.Io.Dir.cwd().createFile(io, probe, .{ .truncate = true }) catch |e| {
            const msg = try std.fmt.allocPrint(a, "cannot write in '{s}' ({s})", .{ full, @errorName(e) });
            const hint = try a.dupe(u8, "fix permissions for this path");
            try addCheck(a, checks, .fail, "paths.writable", msg, hint);
            continue;
        };
        f.close(io);
        _ = std.Io.Dir.cwd().deleteFile(io, probe) catch {};

        const msg = try std.fmt.allocPrint(a, "writable: {s}", .{full});
        try addCheck(a, checks, .ok, "paths.writable", msg, null);
    }
}

fn appendUniquePath(paths: *std.array_list.Managed([]const u8), p: []const u8) !void {
    for (paths.items) |existing| {
        if (std.mem.eql(u8, existing, p)) return;
    }
    try paths.append(p);
}

fn resolvePathAlloc(a: std.mem.Allocator, workspace_root: []const u8, p: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(p)) return a.dupe(u8, p);
    return std.fs.path.join(a, &.{ workspace_root, p });
}

fn activePreset(cfg: config_mod.Config) config_mod.PresetConfig {
    for (cfg.capabilities.presets) |p| {
        if (std.mem.eql(u8, p.name, cfg.capabilities.active_preset)) return p;
    }
    return cfg.capabilities.presets[0];
}

fn commandInPath(a: std.mem.Allocator, io: std.Io, name: []const u8) !bool {
    const path_c = std.c.getenv("PATH") orelse return false;
    const path = std.mem.span(path_c);
    if (path.len == 0) return false;

    var it = std.mem.splitScalar(u8, path, std.fs.path.delimiter);
    while (it.next()) |dir_path| {
        if (dir_path.len == 0) continue;

        const candidate = try std.fs.path.join(a, &.{ dir_path, name });
        defer a.free(candidate);
        if (std.Io.Dir.cwd().statFile(io, candidate, .{})) |_| return true else |_| {}
    }
    return false;
}

fn addCheck(a: std.mem.Allocator, checks: *CheckList, level: Level, id: []const u8, message: []const u8, hint: ?[]const u8) !void {
    try checks.append(.{
        .id = try a.dupe(u8, id),
        .level = level,
        .message = message,
        .hint = hint,
    });
}

fn finalizeReport(checks: *CheckList) !Report {
    var ok_count: usize = 0;
    var warn_count: usize = 0;
    var fail_count: usize = 0;
    for (checks.items) |c| switch (c.level) {
        .ok => ok_count += 1,
        .warn => warn_count += 1,
        .fail => fail_count += 1,
    };
    const owned = try checks.toOwnedSlice();
    return .{
        .checks = owned,
        .ok_count = ok_count,
        .warn_count = warn_count,
        .fail_count = fail_count,
    };
}

fn freeChecks(a: std.mem.Allocator, checks: []Check) void {
    for (checks) |c| {
        a.free(c.id);
        a.free(c.message);
        if (c.hint) |h| a.free(h);
    }
}

fn printText(io: std.Io, cfg_path: []const u8, report: Report) !void {
    const term = @import("util/term.zig");
    const color = term.stdoutSupportsColor();
    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.print("zigclaw doctor --config {s}\n", .{cfg_path});
    try ow.interface.print("summary: ok={d} warn={d} fail={d}\n\n", .{ report.ok_count, report.warn_count, report.fail_count });

    for (report.checks) |c| {
        const level_style: term.Style = switch (c.level) {
            .ok => .green,
            .warn => .yellow,
            .fail => .red,
        };
        try ow.interface.writeAll("[");
        try term.writeStyled(&ow.interface, level_style, levelName(c.level), color);
        try ow.interface.print("] {s}: {s}\n", .{ c.id, c.message });
        if (c.hint) |h| {
            try ow.interface.writeAll("  ");
            try term.writeStyled(&ow.interface, .yellow, "hint:", color);
            try ow.interface.print(" {s}\n", .{h});
        }
    }
    try ow.flush();
}

fn printJson(a: std.mem.Allocator, io: std.Io, cfg_path: []const u8, report: Report) !void {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("ok");
    try stream.write(report.fail_count == 0);
    try stream.objectField("config");
    try stream.write(cfg_path);
    try stream.objectField("summary");
    try stream.beginObject();
    try stream.objectField("ok");
    try stream.write(report.ok_count);
    try stream.objectField("warn");
    try stream.write(report.warn_count);
    try stream.objectField("fail");
    try stream.write(report.fail_count);
    try stream.endObject();

    try stream.objectField("checks");
    try stream.beginArray();
    for (report.checks) |c| {
        try stream.beginObject();
        try stream.objectField("id");
        try stream.write(c.id);
        try stream.objectField("level");
        try stream.write(levelName(c.level));
        try stream.objectField("message");
        try stream.write(c.message);
        if (c.hint) |h| {
            try stream.objectField("hint");
            try stream.write(h);
        }
        try stream.endObject();
    }
    try stream.endArray();
    try stream.endObject();

    const out = try aw.toOwnedSlice();
    defer a.free(out);

    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.print("{s}\n", .{out});
    try ow.flush();
}

fn levelName(level: Level) []const u8 {
    return switch (level) {
        .ok => "ok",
        .warn => "warn",
        .fail => "fail",
    };
}
