const std = @import("std");
const App = @import("../app.zig").App;
const config = @import("../config.zig");
const http = @import("http.zig");
const pairing = @import("../security/pairing.zig");
const tools_rt = @import("../tools/manifest_runtime.zig");
const agent_loop = @import("../agent/loop.zig");
const queue_worker = @import("../queue/worker.zig");
const decision_log = @import("../decision_log.zig");

pub const Resp = struct {
    status: u16,
    body: []u8,

    pub fn deinit(self: *Resp, a: std.mem.Allocator) void {
        a.free(self.body);
    }
};

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
