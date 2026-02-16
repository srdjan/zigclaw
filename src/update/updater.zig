const std = @import("std");
const build_options = @import("build_options");
const platform = @import("platform.zig");

pub const UpdateError = error{
    UnsupportedPlatform,
    ManifestFetchFailed,
    InvalidManifest,
    PlatformNotInManifest,
    ChecksumMismatch,
    DownloadFailed,
    ReplaceFailed,
    AlreadyUpToDate,
} || std.mem.Allocator.Error || std.Io.Writer.Error;

pub const CheckResult = struct {
    current: []const u8,
    latest: []const u8,
    update_available: bool,
    download_url: ?[]const u8,
};

pub fn check(a: std.mem.Allocator, io: std.Io, manifest_url: []const u8) UpdateError!CheckResult {
    const manifest_json = fetchUrl(a, io, manifest_url) catch return error.ManifestFetchFailed;
    defer a.free(manifest_json);

    var parsed = std.json.parseFromSlice(std.json.Value, a, manifest_json, .{}) catch return error.InvalidManifest;
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidManifest;
    const obj = parsed.value.object;

    const latest_version = blk: {
        const v = obj.get("version") orelse return error.InvalidManifest;
        if (v != .string) return error.InvalidManifest;
        break :blk v.string;
    };

    const plat_key = platform.platformKey() orelse return error.UnsupportedPlatform;

    const platforms_v = obj.get("platforms") orelse return error.InvalidManifest;
    if (platforms_v != .object) return error.InvalidManifest;
    const plat_obj_v = platforms_v.object.get(plat_key) orelse return error.PlatformNotInManifest;
    if (plat_obj_v != .object) return error.InvalidManifest;

    const url_v = plat_obj_v.object.get("url") orelse return error.InvalidManifest;
    if (url_v != .string) return error.InvalidManifest;

    const update_available = !std.mem.eql(u8, build_options.version, latest_version);

    return .{
        .current = build_options.version,
        .latest = try a.dupe(u8, latest_version),
        .update_available = update_available,
        .download_url = if (update_available) try a.dupe(u8, url_v.string) else null,
    };
}

pub fn update(a: std.mem.Allocator, io: std.Io, manifest_url: []const u8) UpdateError![]const u8 {
    const manifest_json = fetchUrl(a, io, manifest_url) catch return error.ManifestFetchFailed;
    defer a.free(manifest_json);

    var parsed = std.json.parseFromSlice(std.json.Value, a, manifest_json, .{}) catch return error.InvalidManifest;
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidManifest;
    const obj = parsed.value.object;

    const latest_version = blk: {
        const v = obj.get("version") orelse return error.InvalidManifest;
        if (v != .string) return error.InvalidManifest;
        break :blk v.string;
    };

    if (std.mem.eql(u8, build_options.version, latest_version)) return error.AlreadyUpToDate;

    const plat_key = platform.platformKey() orelse return error.UnsupportedPlatform;

    const platforms_v = obj.get("platforms") orelse return error.InvalidManifest;
    if (platforms_v != .object) return error.InvalidManifest;
    const plat_obj_v = platforms_v.object.get(plat_key) orelse return error.PlatformNotInManifest;
    if (plat_obj_v != .object) return error.InvalidManifest;

    const download_url = blk: {
        const v = plat_obj_v.object.get("url") orelse return error.InvalidManifest;
        if (v != .string) return error.InvalidManifest;
        break :blk v.string;
    };
    const expected_sha = blk: {
        const v = plat_obj_v.object.get("sha256") orelse return error.InvalidManifest;
        if (v != .string) return error.InvalidManifest;
        break :blk v.string;
    };

    // Download binary
    const binary = fetchUrl(a, io, download_url) catch return error.DownloadFailed;
    defer a.free(binary);

    // Verify SHA-256
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(binary);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var computed_hex: [64]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        computed_hex[i * 2] = hex_chars[(b >> 4) & 0xF];
        computed_hex[i * 2 + 1] = hex_chars[b & 0xF];
    }

    if (!std.mem.eql(u8, &computed_hex, expected_sha)) return error.ChecksumMismatch;

    // Atomic replacement: write to .new, rename current to .old, rename .new to current
    const self_path = selfExePath(a, io) catch return error.ReplaceFailed;
    defer a.free(self_path);

    const new_path = std.fmt.allocPrint(a, "{s}.new", .{self_path}) catch return error.ReplaceFailed;
    defer a.free(new_path);
    const old_path = std.fmt.allocPrint(a, "{s}.old", .{self_path}) catch return error.ReplaceFailed;
    defer a.free(old_path);

    const dir = std.Io.Dir.cwd();

    // Write new binary
    blk: {
        var f = dir.createFile(io, new_path, .{ .truncate = true }) catch break :blk;
        defer f.close(io);
        var buf: [8192]u8 = undefined;
        var w = f.writer(io, &buf);
        w.interface.writeAll(binary) catch break :blk;
        w.flush() catch break :blk;
    }

    // Make executable (on unix)
    chmodExec(a, io, new_path);

    // Rename current -> .old (best effort)
    _ = std.Io.Dir.rename(dir, self_path, dir, old_path, io) catch {};

    // Rename .new -> current
    std.Io.Dir.rename(dir, new_path, dir, self_path, io) catch return error.ReplaceFailed;

    return try a.dupe(u8, latest_version);
}

fn selfExePath(a: std.mem.Allocator, io: std.Io) ![]u8 {
    // Try /proc/self/exe on Linux
    var link_buf: [4096]u8 = undefined;
    const n = std.Io.Dir.cwd().readLink(io, "/proc/self/exe", &link_buf) catch {
        // Fallback: use `which zigclaw` to find installed binary
        return whichZigclaw(a, io) catch try a.dupe(u8, "zigclaw");
    };
    return try a.dupe(u8, link_buf[0..n]);
}

fn whichZigclaw(a: std.mem.Allocator, io: std.Io) ![]u8 {
    const argv = [_][]const u8{ "which", "zigclaw" };
    var child = try std.process.spawn(io, .{
        .argv = &argv,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    var buf: [4096]u8 = undefined;
    var reader = child.stdout.?.reader(io, &buf);
    const out = try reader.interface.allocRemaining(a, std.Io.Limit.limited(4096));
    defer a.free(out);
    _ = child.wait(io) catch {};
    const trimmed = std.mem.trim(u8, out, " \t\r\n");
    if (trimmed.len == 0) return error.NotFound;
    return try a.dupe(u8, trimmed);
}

fn chmodExec(a: std.mem.Allocator, io: std.Io, path: []const u8) void {
    const argv = [_][]const u8{ "chmod", "+x", path };
    var child = std.process.spawn(io, .{
        .argv = &argv,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch return;
    var stdout_buf: [256]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &stdout_buf);
    _ = stdout_reader.interface.allocRemaining(a, std.Io.Limit.limited(256)) catch {};
    _ = child.wait(io) catch {};
}

fn fetchUrl(a: std.mem.Allocator, io: std.Io, url: []const u8) ![]u8 {
    var argv_list = std.array_list.Managed([]const u8).init(a);
    defer argv_list.deinit();

    try argv_list.append("curl");
    try argv_list.append("-sfL");
    try argv_list.append(url);

    var child = try std.process.spawn(io, .{
        .argv = argv_list.items,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    var stdout_buf: [8192]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &stdout_buf);
    const data = try stdout_reader.interface.allocRemaining(a, std.Io.Limit.limited(64 * 1024 * 1024));
    errdefer a.free(data);

    const term = try child.wait(io);
    switch (term) {
        .exited => |code| {
            if (code != 0) {
                a.free(data);
                return error.FetchFailed;
            }
        },
        else => {
            a.free(data);
            return error.FetchFailed;
        },
    }

    return data;
}
