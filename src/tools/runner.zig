const std = @import("std");
const config = @import("../config.zig");
const protocol = @import("protocol.zig");
const manifest_mod = @import("manifest.zig");
const schema = @import("schema.zig");

const obs = @import("../obs/logger.zig");
const trace = @import("../obs/trace.zig");
const hash = @import("../obs/hash.zig");
const decision_log = @import("../decision_log.zig");
const ledger_mod = @import("../attestation/ledger.zig");

pub const ToolRunResult = struct {
    request_id: []u8,
    ok: bool,
    data_json: []u8,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *ToolRunResult, a: std.mem.Allocator) void {
        a.free(self.request_id);
        a.free(self.data_json);
        a.free(self.stdout);
        a.free(self.stderr);
    }

    pub fn toJsonAlloc(self: ToolRunResult, a: std.mem.Allocator) ![]u8 {
        // stable JSON wrapper
        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        var stream: std.json.Stringify = .{ .writer = &aw.writer };

        try stream.beginObject();
        try stream.objectField("request_id");
        try stream.write(self.request_id);
        try stream.objectField("ok");
        try stream.write(self.ok);

        // data_json is already JSON string; embed as parsed if possible, else as string fallback
        try stream.objectField("data");
        const parsed = std.json.parseFromSlice(std.json.Value, a, self.data_json, .{}) catch null;
        if (parsed) |p| {
            defer p.deinit();
            try stream.write(p.value);
        } else {
            try stream.write(self.data_json);
        }

        try stream.objectField("stdout");
        try stream.write(self.stdout);
        try stream.objectField("stderr");
        try stream.write(self.stderr);
        try stream.endObject();

        return try aw.toOwnedSlice();
    }
};

pub const RunMeta = struct {
    prompt_hash: ?[]const u8 = null,
    ledger: ?*ledger_mod.MerkleTree = null,
};

pub fn run(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    request_id: []const u8,
    tool: []const u8,
    args_json: []const u8,
    meta: RunMeta,
) !ToolRunResult {
    var logger = obs.Logger.fromConfig(cfg, io);
    const decisions = decision_log.Logger.fromConfig(cfg, io);

    const args_sha = hash.sha256HexAlloc(a, args_json) catch "";
    defer if (args_sha.len > 0) a.free(args_sha);

    const allowed = cfg.policy.isToolAllowed(tool);

    logger.logJson(a, .tool_run, request_id, .{
        .tool = tool,
        .args_sha256 = args_sha,
        .allowed = allowed,
        .policy_hash = cfg.policy.policyHash(),
    });

    decisions.logAndRecord(a, .{
        .ts_unix_ms = decision_log.nowUnixMs(io),
        .request_id = request_id,
        .prompt_hash = meta.prompt_hash,
        .decision = "tool.allow",
        .subject = tool,
        .allowed = allowed,
        .reason = if (allowed) "allowed by capability preset" else "denied: tool not in capability preset",
        .policy_hash = cfg.policy.policyHash(),
    }, meta.ledger);

    if (!allowed) return error.ToolNotAllowed;

    // Locate manifest and load it
    const manifest_path = try std.fmt.allocPrint(a, "{s}/{s}.toml", .{ cfg.raw.tools.plugin_dir, tool });
    defer a.free(manifest_path);
    var owned = try manifest_mod.loadManifest(a, io, manifest_path);
    defer owned.deinit(a);
    const m = owned.manifest;

    // Fail-closed: tool requiring network must be explicitly allowed (capability preset allow_network=true)
    if (m.requires_network) {
        const network_allowed = cfg.policy.active.allow_network;
        decisions.logAndRecord(a, .{
            .ts_unix_ms = decision_log.nowUnixMs(io),
            .request_id = request_id,
            .prompt_hash = meta.prompt_hash,
            .decision = "tool.network",
            .subject = tool,
            .allowed = network_allowed,
            .reason = if (network_allowed) "allowed: preset permits network" else "denied: tool requires network but preset disallows it",
            .policy_hash = cfg.policy.policyHash(),
        }, meta.ledger);
        if (!network_allowed) return error.ToolNetworkNotAllowed;
    }

    // Validate args against schema
    schema.validateArgs(m.args, args_json) catch return error.InvalidToolArgs;

    const mounts = try cfg.policy.makeMounts(a);
    defer freeMounts(a, mounts);

    // For native tools, pass the actual host workspace root as cwd
    const cwd = if (m.native) cfg.raw.security.workspace_root else "/workspace";

    const req = protocol.ToolRequest{
        .request_id = request_id,
        .tool = tool,
        .args_json = args_json,
        .cwd = cwd,
        .mounts = mounts,
    };

    const payload = try protocol.encodeRequest(a, req);
    defer a.free(payload);

    // Build argv: depends on whether this is a native tool or WASI plugin
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();

    // Track heap-allocated strings for correct cleanup
    var alloc_strings = std.array_list.Managed([]u8).init(a);
    defer {
        for (alloc_strings.items) |s| a.free(s);
        alloc_strings.deinit();
    }

    if (m.native) {
        // Native tool: run the host binary directly
        const plugin_path = try std.fmt.allocPrint(a, "{s}/{s}", .{ cfg.raw.tools.plugin_dir, tool });
        try alloc_strings.append(plugin_path);
        try argv.append(plugin_path);
    } else {
        // WASI plugin: run through wasmtime with preopened directories
        const plugin_path = try std.fmt.allocPrint(a, "{s}/{s}.wasm", .{ cfg.raw.tools.plugin_dir, tool });
        try alloc_strings.append(plugin_path);

        try argv.append(cfg.raw.tools.wasmtime_path);
        for (mounts) |mt| {
            const map = try std.fmt.allocPrint(a, "{s}::{s}", .{ mt.host_path, mt.guest_path });
            try alloc_strings.append(map);
            try argv.append("--mapdir");
            try argv.append(map);
        }
        try argv.append(plugin_path);
    }

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    if (child.stdin) |*stdin| {
        var sbuf: [4096]u8 = undefined;
        var sw = stdin.writer(io, &sbuf);
        try sw.interface.writeAll(payload);
        try sw.flush();
        stdin.close(io);
        child.stdin = null;
    }

    // Watchdog for runtime limit (best-effort)
    const deadline_ms = @as(i64, @intCast(m.max_runtime_ms));
    const wait_res = try waitWithTimeout(&child, io, deadline_ms);

    if (wait_res.timed_out) return error.ToolTimeout;

    // Read bounded outputs
    const stdout_bytes = try readCapped(a, io, child.stdout.?, m.max_stdout_bytes);
    defer a.free(stdout_bytes);

    const stderr_bytes = try readCapped(a, io, child.stderr.?, m.max_stderr_bytes);
    defer a.free(stderr_bytes);

    _ = try child.wait(io);

    var decoded = try protocol.decodeResponse(a, stdout_bytes);
    defer decoded.deinit(a);

    return .{
        .request_id = try a.dupe(u8, request_id),
        .ok = decoded.response.ok,
        .data_json = try a.dupe(u8, decoded.response.data_json),
        .stdout = try a.dupe(u8, decoded.response.stdout),
        .stderr = try a.dupe(u8, decoded.response.stderr),
    };
}

fn freeMounts(a: std.mem.Allocator, mounts: []const @import("../policy.zig").Mount) void {
    for (mounts) |m| {
        if (!m.read_only) a.free(m.guest_path);
    }
    a.free(mounts);
}

fn readCapped(a: std.mem.Allocator, io: std.Io, file: std.Io.File, cap: usize) ![]u8 {
    var rbuf: [4096]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    return try reader.interface.allocRemaining(a, std.Io.Limit.limited(cap));
}

const WaitResult = struct { timed_out: bool };

fn waitWithTimeout(child: *std.process.Child, io: std.Io, max_ms: i64) !WaitResult {
    var done = std.atomic.Value(bool).init(false);

    const waiter = try std.Thread.spawn(.{}, struct {
        fn run(c: *std.process.Child, i: std.Io, d: *std.atomic.Value(bool)) void {
            _ = c.wait(i) catch {};
            d.store(true, .seq_cst);
        }
    }.run, .{ child, io, &done });

    var waited: i64 = 0;
    const step: i64 = 10;
    while (!done.load(.seq_cst)) {
        if (waited >= max_ms) {
            child.kill(io);
            waiter.join();
            return .{ .timed_out = true };
        }
        io.sleep(std.Io.Duration.fromMilliseconds(step), .awake) catch {};
        waited += step;
    }
    waiter.join();
    return .{ .timed_out = false };
}
