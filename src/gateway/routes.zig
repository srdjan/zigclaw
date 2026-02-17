const std = @import("std");
const App = @import("../app.zig").App;
const config = @import("../config.zig");
const http = @import("http.zig");
const pairing = @import("../security/pairing.zig");
const tools_rt = @import("../tools/manifest_runtime.zig");
const agent_loop = @import("../agent/loop.zig");
const queue_worker = @import("../queue/worker.zig");
const decision_log = @import("../decision_log.zig");
const att_receipt = @import("../attestation/receipt.zig");
const replay_capsule = @import("../replay/capsule.zig");
const tasks = @import("../primitives/tasks.zig");

const rate_bucket_count: usize = 128;
const max_client_key_len: usize = 96;

const ClientKey = struct {
    buf: [max_client_key_len]u8 = [_]u8{0} ** max_client_key_len,
    len: u8 = 0,

    fn slice(self: *const ClientKey) []const u8 {
        return self.buf[0..self.len];
    }
};

const RateBucket = struct {
    in_use: bool = false,
    key_hash: u64 = 0,
    key: [max_client_key_len]u8 = [_]u8{0} ** max_client_key_len,
    key_len: u8 = 0,
    window_start_ms: i64 = 0,
    count: u32 = 0,
    last_seen_ms: i64 = 0,
};

const RateResult = struct {
    allowed: bool,
    client_key: ClientKey,
    window_count: u32,
    limit: u32,
    store: config.RateLimitStore,
    degraded: bool = false,
};

var rate_buckets: [rate_bucket_count]RateBucket = [_]RateBucket{.{}} ** rate_bucket_count;
const OpsView = enum { full, state };

pub const Resp = struct {
    status: u16,
    body: []u8,
    content_type: []const u8 = "application/json",

    pub fn deinit(self: *Resp, a: std.mem.Allocator) void {
        a.free(self.body);
    }
};

pub fn resetRateLimiterForTests() void {
    rate_buckets = [_]RateBucket{.{}} ** rate_bucket_count;
}

pub fn handle(a: std.mem.Allocator, io: std.Io, app: *App, cfg: config.ValidatedConfig, req: http.RequestOwned, token: []const u8, request_id: []const u8) !Resp {
    const path, const query = splitTarget(req.target);
    const decisions = decision_log.Logger.fromConfig(cfg, io);

    const bytes_allowed = req.raw.len <= cfg.raw.security.max_request_bytes;
    decisions.log(a, .{
        .ts_unix_ms = decision_log.nowUnixMs(io),
        .request_id = request_id,
        .prompt_hash = null,
        .decision = "gateway.request_bytes",
        .subject = path,
        .allowed = bytes_allowed,
        .reason = if (bytes_allowed) "allowed: request within max_request_bytes" else "denied: request exceeds max_request_bytes",
        .policy_hash = cfg.policy.policyHash(),
    });
    if (!bytes_allowed) return try jsonError(a, 413, request_id, "RequestTooLarge");

    if (std.mem.eql(u8, path, "/health")) {
        const body = try jsonObj(a, .{
            .request_id = request_id,
            .ok = true,
            .policy_hash = cfg.policy.policyHash(),
        });
        return .{ .status = 200, .body = body };
    }

    const rate = checkRateLimit(a, req, cfg, io, request_id);
    if (cfg.raw.gateway.rate_limit_enabled) {
        const store_name = @tagName(rate.store);
        const throttle_reason = if (rate.degraded)
            try std.fmt.allocPrint(a, "allowed (degraded): store={s} unavailable; bypassing limit", .{store_name})
        else if (rate.allowed)
            try std.fmt.allocPrint(a, "allowed: store={s} {d}/{d} requests in current window", .{ store_name, rate.window_count, rate.limit })
        else
            try std.fmt.allocPrint(a, "denied: store={s} {d}/{d} requests in current window", .{ store_name, rate.window_count, rate.limit });
        defer a.free(throttle_reason);

        decisions.log(a, .{
            .ts_unix_ms = decision_log.nowUnixMs(io),
            .request_id = request_id,
            .prompt_hash = null,
            .decision = "gateway.throttle",
            .subject = rate.client_key.slice(),
            .allowed = rate.allowed,
            .reason = throttle_reason,
            .policy_hash = cfg.policy.policyHash(),
        });
        if (!rate.allowed) return try jsonError(a, 429, request_id, "TooManyRequests");
    }

    const authed = isAuthorized(req, token) or (isOpsRoute(path) and isAuthorizedQueryToken(query, token));
    decisions.log(a, .{
        .ts_unix_ms = decision_log.nowUnixMs(io),
        .request_id = request_id,
        .prompt_hash = null,
        .decision = "gateway.auth",
        .subject = path,
        .allowed = authed,
        .reason = if (authed) "allowed: valid auth token" else "denied: missing/invalid auth token",
        .policy_hash = cfg.policy.policyHash(),
    });

    if (!authed) {
        return try jsonError(a, 401, request_id, "missing/invalid auth token");
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, path, "/v1/ops")) {
        const limit: usize = if (queryValue(query, "limit")) |s| std.fmt.parseInt(usize, s, 10) catch 8 else 8;
        const view = parseOpsView(queryValue(query, "view"));
        const body = try opsSnapshotJsonAlloc(a, io, cfg, request_id, @min(limit, 50), view);
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, path, "/ops")) {
        const body = try opsHtmlAlloc(a);
        return .{
            .status = 200,
            .body = body,
            .content_type = "text/html; charset=utf-8",
        };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, path, "/v1/tools")) {
        const tools_json = try tools_rt.listToolsJsonAlloc(a, io, cfg.raw.tools.plugin_dir);
        defer a.free(tools_json);
        var parsed_tools = try std.json.parseFromSlice(std.json.Value, a, tools_json, .{});
        defer parsed_tools.deinit();
        if (parsed_tools.value != .object) return jsonError(a, 500, request_id, "InvalidToolList");
        const tools_v = parsed_tools.value.object.get("tools") orelse return jsonError(a, 500, request_id, "InvalidToolList");
        const body = try jsonWithEmbeddedFieldAlloc(a, request_id, "tools", tools_v);
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.startsWith(u8, path, "/v1/tools/")) {
        const tool = path["/v1/tools/".len..];
        if (tool.len == 0) return try jsonError(a, 400, request_id, "tool name required");
        const manifest_json = try tools_rt.describeToolJsonAlloc(a, io, cfg.raw.tools.plugin_dir, tool);
        defer a.free(manifest_json);
        const body = try jsonWithEmbeddedJsonFieldAlloc(a, request_id, "manifest", manifest_json);
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, path, "/v1/tools/run")) {
        const parsed = std.json.parseFromSlice(std.json.Value, a, req.body, .{}) catch return jsonError(a, 400, request_id, "invalid JSON");
        defer parsed.deinit();

        const obj = parsed.value.object;
        const tool_v = obj.get("tool") orelse return jsonError(a, 400, request_id, "missing 'tool'");
        if (tool_v != .string) return jsonError(a, 400, request_id, "'tool' must be string");
        const tool = tool_v.string;

        const args_v = obj.get("args") orelse return jsonError(a, 400, request_id, "missing 'args'");
        const args_json = try stringifyJsonValue(a, args_v);
        defer a.free(args_json);

        var res = app.runToolWithRequestId(a, cfg, request_id, tool, args_json) catch |e| {
            return jsonError(a, 500, request_id, @errorName(e));
        };
        defer res.deinit(a);

        const result_json = try res.toJsonAlloc(a);
        defer a.free(result_json);

        const body = try jsonWithEmbeddedJsonFieldAlloc(a, request_id, "result", result_json);
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, path, "/v1/agent/enqueue")) {
        const parsed = std.json.parseFromSlice(std.json.Value, a, req.body, .{}) catch return jsonError(a, 400, request_id, "invalid JSON");
        defer parsed.deinit();

        const obj = parsed.value.object;
        const msg_v = obj.get("message") orelse return jsonError(a, 400, request_id, "missing 'message'");
        if (msg_v != .string) return jsonError(a, 400, request_id, "'message' must be string");
        const msg = msg_v.string;

        const req_id: ?[]const u8 = if (obj.get("request_id")) |rid_v| switch (rid_v) {
            .string => |s| s,
            else => return jsonError(a, 400, request_id, "'request_id' must be string"),
        } else null;

        const agent_id: ?[]const u8 = if (obj.get("agent_id")) |aid_v| switch (aid_v) {
            .string => |s| s,
            else => return jsonError(a, 400, request_id, "'agent_id' must be string"),
        } else null;

        const queued_id = queue_worker.enqueueAgent(a, io, cfg, msg, agent_id, req_id) catch |e| switch (e) {
            error.InvalidArgs => return jsonError(a, 400, request_id, @errorName(e)),
            error.DuplicateRequestId => return jsonError(a, 409, request_id, @errorName(e)),
            else => return jsonError(a, 500, request_id, @errorName(e)),
        };
        defer a.free(queued_id);

        const body = try jsonObj(a, .{ .request_id = queued_id, .queued = true });
        return .{ .status = 202, .body = body };
    }

    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, path, "/v1/events")) {
        const parsed = std.json.parseFromSlice(std.json.Value, a, req.body, .{}) catch return jsonError(a, 400, request_id, "invalid JSON");
        defer parsed.deinit();
        if (parsed.value != .object) return jsonError(a, 400, request_id, "payload must be object");
        const obj = parsed.value.object;

        const title = blk: {
            if (obj.get("title")) |t| {
                if (t != .string) return jsonError(a, 400, request_id, "'title' must be string");
                break :blk t.string;
            }
            if (obj.get("message")) |m| {
                if (m != .string) return jsonError(a, 400, request_id, "'message' must be string");
                break :blk m.string;
            }
            return jsonError(a, 400, request_id, "missing 'title' or 'message'");
        };

        const priority = if (obj.get("priority")) |v| switch (v) {
            .string => |s| s,
            else => return jsonError(a, 400, request_id, "'priority' must be string"),
        } else null;
        const owner = if (obj.get("owner")) |v| switch (v) {
            .string => |s| s,
            else => return jsonError(a, 400, request_id, "'owner' must be string"),
        } else null;
        const project = if (obj.get("project")) |v| switch (v) {
            .string => |s| s,
            else => return jsonError(a, 400, request_id, "'project' must be string"),
        } else null;
        const tags = if (obj.get("tags")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;
        const context = if (obj.get("context")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        const event_id = blk: {
            if (obj.get("idempotency_key")) |v| {
                if (v != .string) return jsonError(a, 400, request_id, "'idempotency_key' must be string");
                break :blk v.string;
            }
            if (obj.get("id")) |v| {
                if (v != .string) return jsonError(a, 400, request_id, "'id' must be string");
                break :blk v.string;
            }
            break :blk null;
        };

        var created = tasks.addTask(a, io, cfg, .{
            .title = title,
            .priority = priority,
            .owner = owner,
            .project = project,
            .tags = tags,
            .body = context,
            .event_id = event_id,
        }) catch |e| switch (e) {
            error.InvalidArgs,
            error.RequiredFieldMissing,
            error.TemplateTypeMismatch,
            error.TemplateEnumViolation,
            => return jsonError(a, 400, request_id, @errorName(e)),
            else => return jsonError(a, 500, request_id, @errorName(e)),
        };
        defer created.deinit(a);

        const body = try jsonObj(a, .{
            .request_id = request_id,
            .created = created.created,
            .task_slug = created.slug,
            .task_path = created.path,
        });
        return .{ .status = 202, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, path, "/v1/queue/metrics")) {
        const body = queue_worker.metricsJsonAlloc(a, io, cfg) catch |e| switch (e) {
            else => return jsonError(a, 500, request_id, @errorName(e)),
        };
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, path, "/v1/queue/requests")) {
        const limit: usize = if (queryValue(query, "limit")) |s| std.fmt.parseInt(usize, s, 10) catch 50 else 50;
        const filter = parseQueueRequestsFilter(queryValue(query, "state")) orelse return jsonError(a, 400, request_id, "invalid queue state filter");
        const body = queue_worker.listRequestsJsonAlloc(a, io, cfg, @min(limit, 200), filter) catch |e| switch (e) {
            else => return jsonError(a, 500, request_id, @errorName(e)),
        };
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "POST") and std.mem.startsWith(u8, path, "/v1/requests/") and std.mem.endsWith(u8, path, "/cancel")) {
        const rid = requestIdFromCancelPath(path) orelse return jsonError(a, 400, request_id, "request id required");
        const body = queue_worker.cancelRequestJsonAlloc(a, io, cfg, rid) catch |e| switch (e) {
            error.InvalidArgs => return jsonError(a, 400, request_id, @errorName(e)),
            else => return jsonError(a, 500, request_id, @errorName(e)),
        };
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.startsWith(u8, path, "/v1/runs/") and std.mem.endsWith(u8, path, "/summary")) {
        const rid = requestIdFromRunSummaryPath(path) orelse return jsonError(a, 400, request_id, "request id required");
        const body = queue_worker.runSummaryJsonAlloc(a, io, cfg, rid) catch |e| switch (e) {
            error.InvalidArgs => return jsonError(a, 400, request_id, @errorName(e)),
            else => return jsonError(a, 500, request_id, @errorName(e)),
        };
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.startsWith(u8, path, "/v1/requests/")) {
        const rid = path["/v1/requests/".len..];
        if (rid.len == 0) return try jsonError(a, 400, request_id, "request id required");

        const include_payload = queryHasTruthy(query, "include_payload");
        const body = queue_worker.statusJsonAlloc(a, io, cfg, rid, include_payload) catch |e| switch (e) {
            error.InvalidArgs => return jsonError(a, 400, request_id, @errorName(e)),
            else => return jsonError(a, 500, request_id, @errorName(e)),
        };
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, path, "/v1/agent")) {
        const parsed = std.json.parseFromSlice(std.json.Value, a, req.body, .{}) catch return jsonError(a, 400, request_id, "invalid JSON");
        defer parsed.deinit();

        const obj = parsed.value.object;
        const msg_v = obj.get("message") orelse return jsonError(a, 400, request_id, "missing 'message'");
        if (msg_v != .string) return jsonError(a, 400, request_id, "'message' must be string");
        const msg = msg_v.string;

        var result = agent_loop.runLoop(a, io, cfg, msg, request_id, .{}) catch |e| {
            return jsonError(a, 500, request_id, @errorName(e));
        };
        defer result.deinit(a);

        const body = if (result.attestation) |att|
            try jsonObj(a, .{
                .request_id = request_id,
                .content = result.content,
                .turns = result.turns,
                .merkle_root = att.merkle_root_hex[0..],
                .event_count = att.event_count,
            })
        else
            try jsonObj(a, .{ .request_id = request_id, .content = result.content, .turns = result.turns });
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.startsWith(u8, path, "/v1/receipts/")) {
        const rid = path["/v1/receipts/".len..];
        if (rid.len == 0) return try jsonError(a, 400, request_id, "request id required");
        const body = att_receipt.readReceiptJsonAlloc(a, io, cfg.raw.security.workspace_root, rid) catch |e| switch (e) {
            error.FileNotFound => return jsonError(a, 404, request_id, @errorName(e)),
            else => return jsonError(a, 500, request_id, @errorName(e)),
        };
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.startsWith(u8, path, "/v1/capsules/")) {
        const rid = path["/v1/capsules/".len..];
        if (rid.len == 0) return try jsonError(a, 400, request_id, "request id required");
        const body = replay_capsule.readCapsuleJsonAlloc(a, io, cfg.raw.security.workspace_root, rid) catch |e| switch (e) {
            error.FileNotFound => return jsonError(a, 404, request_id, @errorName(e)),
            else => return jsonError(a, 500, request_id, @errorName(e)),
        };
        return .{ .status = 200, .body = body };
    }

    return try jsonError(a, 404, request_id, "not found");
}

fn checkRateLimit(a: std.mem.Allocator, req: http.RequestOwned, cfg: config.ValidatedConfig, io: std.Io, request_id: []const u8) RateResult {
    const gcfg = cfg.raw.gateway;
    const key = clientKeyFromRequest(req);
    if (!gcfg.rate_limit_enabled) {
        return .{
            .allowed = true,
            .client_key = key,
            .window_count = 0,
            .limit = if (gcfg.rate_limit_max_requests == 0) 1 else gcfg.rate_limit_max_requests,
            .store = gcfg.rate_limit_store,
        };
    }

    return switch (gcfg.rate_limit_store) {
        .memory => checkRateLimitMemory(key, gcfg, io),
        .file => checkRateLimitFile(a, key, cfg.raw.security.workspace_root, gcfg, io, request_id) catch .{
            .allowed = true,
            .client_key = key,
            .window_count = 0,
            .limit = if (gcfg.rate_limit_max_requests == 0) 1 else gcfg.rate_limit_max_requests,
            .store = .file,
            .degraded = true,
        },
    };
}

fn checkRateLimitMemory(key: ClientKey, gcfg: config.GatewayConfig, io: std.Io) RateResult {
    const now_ms = decision_log.nowUnixMs(io);
    const window_ms: i64 = @intCast(if (gcfg.rate_limit_window_ms == 0) 1 else gcfg.rate_limit_window_ms);
    const limit: u32 = if (gcfg.rate_limit_max_requests == 0) 1 else gcfg.rate_limit_max_requests;

    const h = hashClientKey(key.slice());
    const bucket = findOrInitBucket(key.slice(), h, now_ms, window_ms);

    if (now_ms - bucket.window_start_ms >= window_ms) {
        bucket.window_start_ms = now_ms;
        bucket.count = 0;
    }

    var allowed = false;
    if (bucket.count < limit) {
        bucket.count += 1;
        allowed = true;
    }
    bucket.last_seen_ms = now_ms;

    return .{
        .allowed = allowed,
        .client_key = key,
        .window_count = bucket.count,
        .limit = limit,
        .store = .memory,
    };
}

fn checkRateLimitFile(
    a: std.mem.Allocator,
    key: ClientKey,
    workspace_root: []const u8,
    gcfg: config.GatewayConfig,
    io: std.Io,
    request_id: []const u8,
) !RateResult {
    const now_ms = decision_log.nowUnixMs(io);
    const window_ms: i64 = @intCast(if (gcfg.rate_limit_window_ms == 0) 1 else gcfg.rate_limit_window_ms);
    const limit: u32 = if (gcfg.rate_limit_max_requests == 0) 1 else gcfg.rate_limit_max_requests;

    const dir_path = if (std.fs.path.isAbsolute(gcfg.rate_limit_dir))
        try a.dupe(u8, gcfg.rate_limit_dir)
    else
        try std.fs.path.join(a, &.{ workspace_root, gcfg.rate_limit_dir });
    defer a.free(dir_path);
    try std.Io.Dir.cwd().createDirPath(io, dir_path);

    const key_hash = hashClientKey(key.slice());

    const name = try std.fmt.allocPrint(a, "{d}_{x}_{s}.evt", .{ now_ms, key_hash, request_id });
    defer a.free(name);
    const path = try std.fs.path.join(a, &.{ dir_path, name });
    defer a.free(path);

    var f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer f.close(io);
    var buf: [128]u8 = undefined;
    var w = f.writer(io, &buf);
    try w.interface.writeAll(key.slice());
    try w.interface.writeAll("\n");
    try w.flush();

    const oldest_keep = now_ms - window_ms * 2;
    const window_start = now_ms - window_ms;
    var count: u32 = 0;

    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return error.OpenDirFailed;
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!std.mem.endsWith(u8, ent.name, ".evt")) continue;

        const parsed = parseRateEntryName(ent.name) orelse continue;
        if (parsed.ts_ms < oldest_keep) {
            const stale_path = try std.fs.path.join(a, &.{ dir_path, ent.name });
            defer a.free(stale_path);
            _ = std.Io.Dir.cwd().deleteFile(io, stale_path) catch {};
            continue;
        }
        if (parsed.ts_ms < window_start) continue;
        if (parsed.key_hash != key_hash) continue;

        const ep = try std.fs.path.join(a, &.{ dir_path, ent.name });
        defer a.free(ep);
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, ep, a, std.Io.Limit.limited(256)) catch continue;
        defer a.free(bytes);
        const stored = std.mem.trim(u8, bytes, " \t\r\n");
        if (!std.mem.eql(u8, stored, key.slice())) continue;

        count += 1;
    }

    return .{
        .allowed = count <= limit,
        .client_key = key,
        .window_count = count,
        .limit = limit,
        .store = .file,
    };
}

const RateEntryName = struct {
    ts_ms: i64,
    key_hash: u64,
};

fn parseRateEntryName(name: []const u8) ?RateEntryName {
    if (!std.mem.endsWith(u8, name, ".evt")) return null;
    const base = name[0 .. name.len - ".evt".len];
    const us1 = std.mem.indexOfScalar(u8, base, '_') orelse return null;
    const us2_rel = std.mem.indexOfScalar(u8, base[us1 + 1 ..], '_') orelse return null;
    const us2 = us1 + 1 + us2_rel;
    if (us1 == 0 or us2 <= us1 + 1) return null;

    const ts_ms = std.fmt.parseInt(i64, base[0..us1], 10) catch return null;
    const key_hash = std.fmt.parseInt(u64, base[us1 + 1 .. us2], 16) catch return null;
    return .{ .ts_ms = ts_ms, .key_hash = key_hash };
}

fn hashClientKey(key: []const u8) u64 {
    var h = std.hash.Wyhash.init(0x517cc1b727220a95);
    h.update(key);
    return h.final();
}

fn findOrInitBucket(key: []const u8, key_hash: u64, now_ms: i64, window_ms: i64) *RateBucket {
    const start = @as(usize, @intCast(key_hash % rate_bucket_count));
    const stale_after = window_ms * 4;
    var candidate_idx: ?usize = null;

    var i: usize = 0;
    while (i < rate_bucket_count) : (i += 1) {
        const idx = (start + i) % rate_bucket_count;
        const b = &rate_buckets[idx];

        if (b.in_use) {
            if (b.key_hash == key_hash and bucketKeyEq(b.*, key)) return b;
            if (candidate_idx == null and now_ms - b.last_seen_ms > stale_after) candidate_idx = idx;
            continue;
        }

        if (candidate_idx == null) candidate_idx = idx;
    }

    const idx = candidate_idx orelse start;
    var out = &rate_buckets[idx];
    out.in_use = true;
    out.key_hash = key_hash;
    out.key_len = @intCast(key.len);
    @memcpy(out.key[0..key.len], key);
    out.window_start_ms = now_ms;
    out.last_seen_ms = now_ms;
    out.count = 0;
    return out;
}

fn bucketKeyEq(b: RateBucket, key: []const u8) bool {
    return b.key_len == key.len and std.mem.eql(u8, b.key[0..b.key_len], key);
}

fn clientKeyFromRequest(req: http.RequestOwned) ClientKey {
    var out = ClientKey{};
    const raw = rawClientId(req);

    if (raw.len == 0) {
        const s = "anon";
        out.len = @intCast(s.len);
        @memcpy(out.buf[0..s.len], s);
        return out;
    }

    if (raw.len <= max_client_key_len) {
        out.len = @intCast(raw.len);
        @memcpy(out.buf[0..raw.len], raw);
        return out;
    }

    const h = hashClientKey(raw);
    const key = std.fmt.bufPrint(&out.buf, "h:{x}", .{h}) catch "anon";
    out.len = @intCast(key.len);
    return out;
}

fn rawClientId(req: http.RequestOwned) []const u8 {
    if (req.header("authorization")) |auth| {
        const prefix = "Bearer ";
        if (std.mem.startsWith(u8, auth, prefix)) {
            return std.mem.trim(u8, auth[prefix.len..], " \t\r\n");
        }
    }
    if (req.header("x-client-id")) |cid| {
        const t = std.mem.trim(u8, cid, " \t\r\n");
        if (t.len > 0) return t;
    }
    if (req.header("x-forwarded-for")) |xff| {
        const first = if (std.mem.indexOfScalar(u8, xff, ',')) |i| xff[0..i] else xff;
        const t = std.mem.trim(u8, first, " \t\r\n");
        if (t.len > 0) return t;
    }
    return "";
}

fn isAuthorized(req: http.RequestOwned, token: []const u8) bool {
    const auth = req.header("authorization") orelse return false;
    const prefix = "Bearer ";
    if (!std.mem.startsWith(u8, auth, prefix)) return false;
    const got = std.mem.trim(u8, auth[prefix.len..], " \t\r\n");
    return pairing.constantTimeEq(got, token);
}

fn stringifyJsonValue(a: std.mem.Allocator, v: std.json.Value) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.write(v);
    return try aw.toOwnedSlice();
}

fn jsonWithEmbeddedJsonFieldAlloc(
    a: std.mem.Allocator,
    request_id: []const u8,
    field_name: []const u8,
    embedded_json: []const u8,
) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, embedded_json, .{});
    defer parsed.deinit();
    return try jsonWithEmbeddedFieldAlloc(a, request_id, field_name, parsed.value);
}

fn jsonWithEmbeddedFieldAlloc(
    a: std.mem.Allocator,
    request_id: []const u8,
    field_name: []const u8,
    value: std.json.Value,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField(field_name);
    try stream.write(value);
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn jsonError(a: std.mem.Allocator, status: u16, request_id: []const u8, msg: []const u8) !Resp {
    const body = try jsonObj(a, .{ .request_id = request_id, .@"error" = msg });
    return .{ .status = status, .body = body };
}

fn jsonObj(a: std.mem.Allocator, payload: anytype) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.write(payload);
    return try aw.toOwnedSlice();
}

fn splitTarget(target: []const u8) struct { []const u8, ?[]const u8 } {
    if (std.mem.indexOfScalar(u8, target, '?')) |i| {
        return .{ target[0..i], target[i + 1 ..] };
    }
    return .{ target, null };
}

fn queryHasTruthy(query: ?[]const u8, key: []const u8) bool {
    const q = query orelse return false;
    var it = std.mem.splitScalar(u8, q, '&');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, part, '=');
        const k = if (eq) |i| part[0..i] else part;
        const v = if (eq) |i| part[i + 1 ..] else "";
        if (!std.mem.eql(u8, k, key)) continue;
        if (v.len == 0) return true;
        if (std.mem.eql(u8, v, "1")) return true;
        if (std.ascii.eqlIgnoreCase(v, "true")) return true;
        if (std.ascii.eqlIgnoreCase(v, "yes")) return true;
        return false;
    }
    return false;
}

fn queryValue(query: ?[]const u8, key: []const u8) ?[]const u8 {
    const q = query orelse return null;
    var it = std.mem.splitScalar(u8, q, '&');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const k = part[0..eq];
        const v = part[eq + 1 ..];
        if (std.mem.eql(u8, k, key)) return v;
    }
    return null;
}

fn isOpsRoute(path: []const u8) bool {
    return std.mem.eql(u8, path, "/ops") or std.mem.eql(u8, path, "/v1/ops");
}

fn isAuthorizedQueryToken(query: ?[]const u8, token: []const u8) bool {
    const got = queryValue(query, "token") orelse return false;
    return pairing.constantTimeEq(got, token);
}

fn parseOpsView(raw: ?[]const u8) OpsView {
    const v = raw orelse return .full;
    if (std.ascii.eqlIgnoreCase(v, "state")) return .state;
    return .full;
}

fn parseQueueRequestsFilter(raw: ?[]const u8) ?queue_worker.RequestListFilter {
    const v = raw orelse return .all;
    if (std.ascii.eqlIgnoreCase(v, "all")) return .all;
    if (std.ascii.eqlIgnoreCase(v, "queued")) return .queued;
    if (std.ascii.eqlIgnoreCase(v, "processing")) return .processing;
    if (std.ascii.eqlIgnoreCase(v, "completed")) return .completed;
    if (std.ascii.eqlIgnoreCase(v, "canceled")) return .canceled;
    return null;
}

fn opsSnapshotJsonAlloc(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    request_id: []const u8,
    limit: usize,
    view: OpsView,
) ![]u8 {
    const report_mod = @import("../audit/report.zig");
    const log_reader = @import("../audit/log_reader.zig");

    const queue_json = try queue_worker.metricsJsonAlloc(a, io, cfg);
    defer a.free(queue_json);
    var queue_parsed = try std.json.parseFromSlice(std.json.Value, a, queue_json, .{});
    defer queue_parsed.deinit();
    if (queue_parsed.value != .object) return error.InvalidJson;

    if (view == .state) {
        const q = queue_parsed.value.object;
        const incoming_ready = getJsonInt(q, "incoming_ready") orelse 0;
        const processing = getJsonInt(q, "processing") orelse 0;
        const incoming_total = getJsonInt(q, "incoming_total") orelse 0;
        const state = if (processing > 0 or incoming_ready > 0)
            "busy"
        else if (incoming_total > 0)
            "queued"
        else
            "idle";

        var aw: std.Io.Writer.Allocating = .init(a);
        defer aw.deinit();
        var stream: std.json.Stringify = .{ .writer = &aw.writer };
        try stream.beginObject();
        try stream.objectField("request_id");
        try stream.write(request_id);
        try stream.objectField("generated_at_ms");
        try stream.write(decision_log.nowUnixMs(io));
        try stream.objectField("view");
        try stream.write("state");
        try stream.objectField("state");
        try stream.write(state);
        try stream.objectField("queue");
        try stream.write(queue_parsed.value);
        try stream.endObject();
        return try aw.toOwnedSlice();
    }

    const events = try log_reader.readEvents(a, io, cfg.raw.logging.dir, cfg.raw.logging.file, .{});
    defer log_reader.freeEvents(a, events);
    var summary = try report_mod.buildSummary(a, events);
    defer summary.deinit(a);
    const summary_json = try report_mod.formatSummaryJson(a, summary);
    defer a.free(summary_json);
    var summary_parsed = try std.json.parseFromSlice(std.json.Value, a, summary_json, .{});
    defer summary_parsed.deinit();

    const receipts_dir = try std.fs.path.join(a, &.{ cfg.raw.security.workspace_root, ".zigclaw/receipts" });
    defer a.free(receipts_dir);
    const capsules_dir = try std.fs.path.join(a, &.{ cfg.raw.security.workspace_root, ".zigclaw/capsules" });
    defer a.free(capsules_dir);

    const receipts = try listRecentJsonNamesAlloc(a, io, receipts_dir, limit);
    defer freeStringList(a, receipts);
    const capsules = try listRecentJsonNamesAlloc(a, io, capsules_dir, limit);
    defer freeStringList(a, capsules);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("generated_at_ms");
    try stream.write(decision_log.nowUnixMs(io));
    try stream.objectField("view");
    try stream.write("full");
    try stream.objectField("queue");
    try stream.write(queue_parsed.value);
    try stream.objectField("audit_summary");
    try stream.write(summary_parsed.value);
    try stream.objectField("recent_receipts");
    try stream.write(receipts);
    try stream.objectField("recent_capsules");
    try stream.write(capsules);
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn opsHtmlAlloc(a: std.mem.Allocator) ![]u8 {
    return try a.dupe(u8,
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\  <meta charset="utf-8">
        \\  <meta name="viewport" content="width=device-width,initial-scale=1">
        \\  <title>zigclaw ops</title>
        \\  <style>
        \\    :root { color-scheme: light; }
        \\    body { font-family: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; margin: 24px; background: #f5f7fb; color: #10243a; }
        \\    h1 { margin: 0 0 10px 0; font-size: 22px; }
        \\    .controls { margin-bottom: 12px; display: flex; gap: 12px; flex-wrap: wrap; align-items: center; color: #345; }
        \\    label { display: inline-flex; gap: 6px; align-items: center; }
        \\    input[type=number] { width: 90px; padding: 4px 6px; border: 1px solid #c7d0dc; border-radius: 6px; }
        \\    #out { background: #fff; border: 1px solid #d8dee7; border-radius: 10px; padding: 16px; white-space: pre-wrap; line-height: 1.45; }
        \\    .err { color: #b01616; }
        \\  </style>
        \\</head>
        \\<body>
        \\  <h1>zigclaw ops</h1>
        \\  <div class="controls">
        \\    <label>limit <input id="limit" type="number" min="1" max="50" step="1" value="8"></label>
        \\    <label>interval_ms <input id="interval" type="number" min="250" max="60000" step="250" value="2000"></label>
        \\    <label><input id="stateOnly" type="checkbox"> state-only</label>
        \\  </div>
        \\  <pre id="out">loading...</pre>
        \\  <script>
        \\    const out = document.getElementById("out");
        \\    const limitEl = document.getElementById("limit");
        \\    const intervalEl = document.getElementById("interval");
        \\    const stateOnlyEl = document.getElementById("stateOnly");
        \\    const params = new URLSearchParams(window.location.search);
        \\    const token = params.get("token") || "";
        \\
        \\    function asInt(v, fallback, min, max) {
        \\      const n = Number.parseInt(v || "", 10);
        \\      if (!Number.isFinite(n)) return fallback;
        \\      return Math.max(min, Math.min(max, n));
        \\    }
        \\
        \\    function isStateView(v) {
        \\      if (!v) return false;
        \\      const t = String(v).toLowerCase();
        \\      return t === "state" || t === "1" || t === "true" || t === "yes";
        \\    }
        \\
        \\    limitEl.value = String(asInt(params.get("limit"), 8, 1, 50));
        \\    intervalEl.value = String(asInt(params.get("interval_ms"), 2000, 250, 60000));
        \\    stateOnlyEl.checked = isStateView(params.get("view"));
        \\
        \\    let timer = null;
        \\
        \\    function currentLimit() {
        \\      const n = asInt(limitEl.value, 8, 1, 50);
        \\      limitEl.value = String(n);
        \\      return n;
        \\    }
        \\
        \\    function currentInterval() {
        \\      const n = asInt(intervalEl.value, 2000, 250, 60000);
        \\      intervalEl.value = String(n);
        \\      return n;
        \\    }
        \\
        \\    function currentView() {
        \\      return stateOnlyEl.checked ? "state" : "full";
        \\    }
        \\
        \\    function endpoint() {
        \\      const q = new URLSearchParams();
        \\      if (token) q.set("token", token);
        \\      q.set("limit", String(currentLimit()));
        \\      q.set("view", currentView());
        \\      return "/v1/ops?" + q.toString();
        \\    }
        \\
        \\    function syncUrl() {
        \\      const q = new URLSearchParams();
        \\      if (token) q.set("token", token);
        \\      q.set("limit", String(currentLimit()));
        \\      q.set("interval_ms", String(currentInterval()));
        \\      q.set("view", currentView());
        \\      history.replaceState(null, "", "/ops?" + q.toString());
        \\    }
        \\
        \\    function renderStateOnly(data) {
        \\      const q = data.queue || {};
        \\      const lines = [];
        \\      lines.push("state=" + (data.state || "unknown"));
        \\      lines.push("generated_at_ms=" + String(data.generated_at_ms || 0));
        \\      lines.push("incoming_total=" + String(q.incoming_total || 0));
        \\      lines.push("incoming_ready=" + String(q.incoming_ready || 0));
        \\      lines.push("processing=" + String(q.processing || 0));
        \\      lines.push("outgoing=" + String(q.outgoing || 0));
        \\      lines.push("canceled=" + String(q.canceled || 0));
        \\      return lines.join("\n");
        \\    }
        \\
        \\    function restartTimer() {
        \\      if (timer) clearInterval(timer);
        \\      timer = setInterval(refresh, currentInterval());
        \\    }
        \\
        \\    async function refresh() {
        \\      syncUrl();
        \\      try {
        \\        const resp = await fetch(endpoint(), { cache: "no-store" });
        \\        if (!resp.ok) {
        \\          out.className = "err";
        \\          out.textContent = "request failed: HTTP " + resp.status;
        \\          return;
        \\        }
        \\        const data = await resp.json();
        \\        out.className = "";
        \\        if (stateOnlyEl.checked) {
        \\          out.textContent = renderStateOnly(data);
        \\        } else {
        \\          out.textContent = JSON.stringify(data, null, 2);
        \\        }
        \\      } catch (e) {
        \\        out.className = "err";
        \\        out.textContent = String(e);
        \\      }
        \\    }
        \\    limitEl.addEventListener("change", refresh);
        \\    stateOnlyEl.addEventListener("change", refresh);
        \\    intervalEl.addEventListener("change", () => { restartTimer(); refresh(); });
        \\    restartTimer();
        \\    refresh();
        \\  </script>
        \\</body>
        \\</html>
    );
}

fn listRecentJsonNamesAlloc(a: std.mem.Allocator, io: std.Io, dir_path: []const u8, limit: usize) ![]const []const u8 {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch {
        return try a.alloc([]const u8, 0);
    };
    defer dir.close(io);

    var names = std.array_list.Managed([]const u8).init(a);
    defer names.deinit();

    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!std.mem.endsWith(u8, ent.name, ".json")) continue;
        try names.append(try a.dupe(u8, ent.name));
    }

    std.sort.block([]const u8, names.items, {}, struct {
        fn gt(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.order(u8, lhs, rhs) == .gt;
        }
    }.gt);

    const take = @min(limit, names.items.len);
    const out = try a.alloc([]const u8, take);
    for (0..take) |i| out[i] = names.items[i];
    for (take..names.items.len) |i| a.free(names.items[i]);
    return out;
}

fn freeStringList(a: std.mem.Allocator, items: []const []const u8) void {
    for (items) |it| a.free(it);
    a.free(items);
}

fn getJsonInt(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}

fn requestIdFromCancelPath(path: []const u8) ?[]const u8 {
    const prefix = "/v1/requests/";
    const suffix = "/cancel";
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    if (!std.mem.endsWith(u8, path, suffix)) return null;
    if (path.len <= prefix.len + suffix.len) return null;

    const rid = path[prefix.len .. path.len - suffix.len];
    if (rid.len == 0) return null;
    if (std.mem.indexOfScalar(u8, rid, '/') != null) return null;
    return rid;
}

fn requestIdFromRunSummaryPath(path: []const u8) ?[]const u8 {
    const prefix = "/v1/runs/";
    const suffix = "/summary";
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    if (!std.mem.endsWith(u8, path, suffix)) return null;
    if (path.len <= prefix.len + suffix.len) return null;

    const rid = path[prefix.len .. path.len - suffix.len];
    if (rid.len == 0) return null;
    if (std.mem.indexOfScalar(u8, rid, '/') != null) return null;
    return rid;
}
