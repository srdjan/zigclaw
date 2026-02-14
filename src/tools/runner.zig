const std = @import("std");
const config = @import("../config.zig");
const protocol = @import("protocol.zig");
const manifest_mod = @import("manifest.zig");
const schema = @import("schema.zig");

const obs = @import("../obs/logger.zig");
const trace = @import("../obs/trace.zig");
const hash = @import("../obs/hash.zig");

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
        var stream = std.json.StringifyStream.init(a);
        defer stream.deinit();

        try stream.beginObject();
        try stream.objectField("request_id"); try stream.write(self.request_id);
        try stream.objectField("ok"); try stream.write(self.ok);

        // data_json is already JSON string; embed as parsed if possible, else as string fallback
        try stream.objectField("data");
        const parsed = std.json.parseFromSlice(std.json.Value, a, self.data_json, .{}) catch null;
        if (parsed) |p| {
            defer p.deinit();
            try stream.write(p.value);
        } else {
            try stream.write(self.data_json);
        }

        try stream.objectField("stdout"); try stream.write(self.stdout);
        try stream.objectField("stderr"); try stream.write(self.stderr);
        try stream.endObject();

        return try stream.toOwnedSlice();
    }
};

pub fn run(
    a: std.mem.Allocator,
    cfg: config.ValidatedConfig,
    request_id: []const u8,
    tool: []const u8,
    args_json: []const u8,
) !ToolRunResult {
    var logger = obs.Logger.fromConfig(cfg);

    const args_sha = hash.sha256HexAlloc(a, args_json) catch "";
    defer if (args_sha.len > 0) a.free(args_sha);

    const allowed = cfg.policy.isToolAllowed(tool);

    logger.logJson(a, .tool_run, request_id, .{
        .tool = tool,
        .args_sha256 = args_sha,
        .allowed = allowed,
        .policy_hash = cfg.policy.policyHash(),
    });

    if (!allowed) return error.ToolNotAllowed;

    // Locate manifest and load it
    const manifest_path = try std.fmt.allocPrint(a, "{s}/{s}.toml", .{ cfg.raw.tools.plugin_dir, tool });
    defer a.free(manifest_path);
    var owned = try manifest_mod.loadManifest(a, manifest_path);
    defer owned.deinit(a);
    const m = owned.manifest;

    // Fail-closed: tool requiring network must be explicitly allowed (capability preset allow_network=true)
    if (m.requires_network and !cfg.policy.active.allow_network) return error.ToolNetworkNotAllowed;

    // Validate args against schema
    schema.validateArgs(m.args, args_json) catch return error.InvalidToolArgs;

    const mounts = try cfg.policy.makeMounts(a);
    defer freeMounts(a, mounts);

    const req = protocol.ToolRequest{
        .request_id = request_id,
        .tool = tool,
        .args_json = args_json,
        .cwd = "/workspace",
        .mounts = mounts,
    };

    const payload = try protocol.encodeRequest(a, req);
    defer a.free(payload);

    // Locate plugin wasm: <plugin_dir>/<tool>.wasm
    const plugin_path = try std.fmt.allocPrint(a, "{s}/{s}.wasm", .{ cfg.raw.tools.plugin_dir, tool });
    defer a.free(plugin_path);

    // Build argv: wasmtime --mapdir HOST::GUEST ... <plugin.wasm>
    var argv = std.ArrayList([]const u8).init(a);
    defer {
        // free map strings
        for (argv.items) |arg| {
            if (std.mem.indexOf(u8, arg, "::") != null and !std.mem.eql(u8, arg, plugin_path) and !std.mem.eql(u8, arg, cfg.raw.tools.wasmtime_path) and !std.mem.eql(u8, arg, "--mapdir")) {
                // best-effort heuristic; safe because strings were allocPrint'd
                a.free(@constCast(arg));
            }
        }
        argv.deinit();
    }

    try argv.append(cfg.raw.tools.wasmtime_path);

    // Preopen dirs for each mount
    for (mounts) |mt| {
        const map = try std.fmt.allocPrint(a, "{s}::{s}", .{ mt.host_path, mt.guest_path });
        try argv.append("--mapdir");
        try argv.append(map);
    }
    try argv.append(plugin_path);

    var child = std.ChildProcess.init(argv.items, a);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    if (child.stdin) |stdin| {
        try stdin.writer().writeAll(payload);
        stdin.close();
    }

    // Watchdog for runtime limit (best-effort)
    const deadline_ms = @as(i64, @intCast(m.max_runtime_ms));
    const wait_res = try waitWithTimeout(&child, deadline_ms);

    if (wait_res.timed_out) {
        _ = child.kill() catch {};
        return error.ToolTimeout;
    }

    // Read bounded outputs
    const stdout_bytes = try readCapped(a, child.stdout.?, m.max_stdout_bytes);
    defer a.free(stdout_bytes);

    const stderr_bytes = try readCapped(a, child.stderr.?, m.max_stderr_bytes);
    defer a.free(stderr_bytes);

    _ = try child.wait();

    const decoded = try protocol.decodeResponse(a, stdout_bytes);
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

fn readCapped(a: std.mem.Allocator, file: std.fs.File, cap: usize) ![]u8 {
    var buf = std.ArrayList(u8).init(a);
    errdefer buf.deinit();

    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = try file.reader().read(&tmp);
        if (n == 0) break;
        if (buf.items.len + n > cap) return error.OutputTooLarge;
        try buf.appendSlice(tmp[0..n]);
    }
    return try buf.toOwnedSlice();
}

const WaitResult = struct { timed_out: bool };

fn waitWithTimeout(child: *std.ChildProcess, max_ms: i64) !WaitResult {
    // Spawn a thread that waits for completion; main thread sleeps/polls.
    var done = std.atomic.Value(bool).init(false);

    const waiter = try std.Thread.spawn(.{}, struct {
        fn run(ctx: struct { child: *std.ChildProcess, done: *std.atomic.Value(bool) }) void {
            _ = ctx.child.wait() catch {};
            ctx.done.store(true, .seq_cst);
        }
    }.run, .{ .child = child, .done = &done });
    waiter.detach();

    var waited: i64 = 0;
    const step: i64 = 10;
    while (!done.load(.seq_cst)) {
        if (waited >= max_ms) return .{ .timed_out = true };
        std.time.sleep(@as(u64, @intCast(step)) * std.time.ns_per_ms);
        waited += step;
    }
    return .{ .timed_out = false };
}
