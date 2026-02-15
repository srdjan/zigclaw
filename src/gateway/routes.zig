const std = @import("std");
const App = @import("../app.zig").App;
const config = @import("../config.zig");
const http = @import("http.zig");
const pairing = @import("../security/pairing.zig");
const tools_rt = @import("../tools/manifest_runtime.zig");

pub const Resp = struct {
    status: u16,
    body: []u8,

    pub fn deinit(self: *Resp, a: std.mem.Allocator) void {
        a.free(self.body);
    }
};

pub fn handle(a: std.mem.Allocator, io: std.Io, app: *App, cfg: config.ValidatedConfig, req: http.RequestOwned, token: []const u8, request_id: []const u8) !Resp {
    if (std.mem.eql(u8, req.target, "/health")) {
        const body = try jsonObj(a, .{
            .request_id = request_id,
            .ok = true,
            .policy_hash = cfg.policy.policyHash(),
        });
        return .{ .status = 200, .body = body };
    }

    if (!isAuthorized(req, token)) {
        return try jsonError(a, 401, request_id, "missing/invalid Authorization Bearer token");
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, req.target, "/v1/tools")) {
        const tools_json = try tools_rt.listToolsJsonAlloc(a, io, cfg.raw.tools.plugin_dir);
        defer a.free(tools_json);
        const body = try jsonObj(a, .{ .request_id = request_id, .tools_json = tools_json });
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "GET") and std.mem.startsWith(u8, req.target, "/v1/tools/")) {
        const tool = req.target["/v1/tools/".len..];
        if (tool.len == 0) return try jsonError(a, 400, request_id, "tool name required");
        const manifest_json = try tools_rt.describeToolJsonAlloc(a, io, cfg.raw.tools.plugin_dir, tool);
        defer a.free(manifest_json);
        const body = try jsonObj(a, .{ .request_id = request_id, .manifest_json = manifest_json });
        return .{ .status = 200, .body = body };
    }

    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, req.target, "/v1/tools/run")) {
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

    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, req.target, "/v1/agent")) {
        const parsed = std.json.parseFromSlice(std.json.Value, a, req.body, .{}) catch return jsonError(a, 400, request_id, "invalid JSON");
        defer parsed.deinit();

        const obj = parsed.value.object;
        const msg_v = obj.get("message") orelse return jsonError(a, 400, request_id, "missing 'message'");
        if (msg_v != .string) return jsonError(a, 400, request_id, "'message' must be string");
        const msg = msg_v.string;

        const content = runAgentOnce(a, io, cfg, msg, request_id) catch |e| {
            return jsonError(a, 500, request_id, @errorName(e));
        };
        defer a.free(content);

        const body = try jsonObj(a, .{ .request_id = request_id, .content = content });
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

// Agent runner that returns response content
fn runAgentOnce(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, message: []const u8, request_id: []const u8) ![]u8 {
    const provider_factory = @import("../providers/factory.zig");
    const bundle = @import("../agent/bundle.zig");
    const obs_mod = @import("../obs/logger.zig");

    var logger = obs_mod.Logger.fromConfig(cfg, io);

    var provider = try provider_factory.build(a, cfg);
    defer provider.deinit(a);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ta = arena.allocator();

    var b = try bundle.build(ta, io, cfg, message);
    defer b.deinit(ta);

    logger.logJson(ta, .agent_run, request_id, .{
        .prompt_hash = b.prompt_hash_hex,
        .provider_kind = @tagName(cfg.raw.provider_primary.kind),
        .model = cfg.raw.provider_primary.model,
        .via = "gateway",
    });

    logger.logJson(ta, .provider_call, request_id, .{
        .kind = @tagName(cfg.raw.provider_primary.kind),
        .model = cfg.raw.provider_primary.model,
        .status = "start",
    });

    const resp = provider.chat(ta, io, .{
        .system = b.system,
        .user = message,
        .model = cfg.raw.provider_primary.model,
        .temperature = cfg.raw.provider_primary.temperature,
        .memory_context = b.memory,
        .meta = .{ .request_id = request_id, .prompt_hash = b.prompt_hash_hex },
    }) catch |e| {
        logger.logJson(ta, .provider_call, request_id, .{
            .kind = @tagName(cfg.raw.provider_primary.kind),
            .model = cfg.raw.provider_primary.model,
            .status = "error",
            .error_name = @errorName(e),
        });
        return e;
    };

    logger.logJson(ta, .provider_call, request_id, .{
        .kind = @tagName(cfg.raw.provider_primary.kind),
        .model = cfg.raw.provider_primary.model,
        .status = "ok",
        .bytes_out = resp.content.len,
    });

    return try a.dupe(u8, resp.content);
}
