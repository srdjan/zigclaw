const std = @import("std");
const App = @import("../app.zig").App;
const config = @import("../config.zig");
const http = @import("http.zig");
const pairing = @import("../security/pairing.zig");
const tools_rt = @import("../tools/manifest_runtime.zig");
const agent_loop = @import("../agent/loop.zig");
const queue_worker = @import("../queue/worker.zig");
const decision_log = @import("../decision_log.zig");

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
};

var rate_buckets: [rate_bucket_count]RateBucket = [_]RateBucket{.{}} ** rate_bucket_count;

pub const Resp = struct {
    status: u16,
    body: []u8,

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

    const rate = checkRateLimit(req, cfg.raw.gateway, io);
    if (cfg.raw.gateway.rate_limit_enabled) {
        const throttle_reason = if (rate.allowed)
            try std.fmt.allocPrint(a, "allowed: {d}/{d} requests in current window", .{ rate.window_count, rate.limit })
        else
            try std.fmt.allocPrint(a, "denied: {d}/{d} requests in current window", .{ rate.window_count, rate.limit });
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

    const authed = isAuthorized(req, token);
    decisions.log(a, .{
        .ts_unix_ms = decision_log.nowUnixMs(io),
        .request_id = request_id,
        .prompt_hash = null,
        .decision = "gateway.auth",
        .subject = path,
        .allowed = authed,
        .reason = if (authed) "allowed: valid bearer token" else "denied: missing/invalid bearer token",
        .policy_hash = cfg.policy.policyHash(),
    });

    if (!authed) {
        return try jsonError(a, 401, request_id, "missing/invalid Authorization Bearer token");
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, path, "/v1/tools")) {
        const tools_json = try tools_rt.listToolsJsonAlloc(a, io, cfg.raw.tools.plugin_dir);
        defer a.free(tools_json);
        const body = try jsonObj(a, .{ .request_id = request_id, .tools_json = tools_json });
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.startsWith(u8, path, "/v1/tools/")) {
        const tool = path["/v1/tools/".len..];
        if (tool.len == 0) return try jsonError(a, 400, request_id, "tool name required");
        const manifest_json = try tools_rt.describeToolJsonAlloc(a, io, cfg.raw.tools.plugin_dir, tool);
        defer a.free(manifest_json);
        const body = try jsonObj(a, .{ .request_id = request_id, .manifest_json = manifest_json });
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

        const body = try jsonObj(a, .{ .request_id = request_id, .result_json = result_json });
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

    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, path, "/v1/queue/metrics")) {
        const body = queue_worker.metricsJsonAlloc(a, io, cfg) catch |e| switch (e) {
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

        const body = try jsonObj(a, .{ .request_id = request_id, .content = result.content, .turns = result.turns });
        return .{ .status = 200, .body = body };
    }

    return try jsonError(a, 404, request_id, "not found");
}

fn checkRateLimit(req: http.RequestOwned, gcfg: config.GatewayConfig, io: std.Io) RateResult {
    const key = clientKeyFromRequest(req);
    if (!gcfg.rate_limit_enabled) {
        return .{
            .allowed = true,
            .client_key = key,
            .window_count = 0,
            .limit = if (gcfg.rate_limit_max_requests == 0) 1 else gcfg.rate_limit_max_requests,
        };
    }

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
    };
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
