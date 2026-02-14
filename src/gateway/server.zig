const std = @import("std");
const App = @import("../app.zig").App;
const config = @import("../config.zig");
const http = @import("http.zig");
const routes = @import("routes.zig");
const token_mod = @import("token.zig");
const trace = @import("../obs/trace.zig");
const obs = @import("../obs/logger.zig");

pub fn start(a: std.mem.Allocator, app: *App, cfg: config.ValidatedConfig, bind: []const u8, port: u16) !void {
    var t = try token_mod.loadOrCreate(a, cfg.raw.security.workspace_root);
    defer t.deinit(a);

    try std.io.getStdOut().writer().print(
        "gateway listening on http://{s}:{d}\nAuthorization: Bearer {s}\n(token stored at {s})\n",
        .{ bind, port, t.token, t.path },
    );

    var server = std.net.StreamServer.init(.{});
    defer server.deinit();

    const addr = try std.net.Address.parseIp(bind, port);
    try server.listen(addr);

    while (true) {
        var conn = try server.accept();
        handleConn(a, app, cfg, conn, t.token) catch |e| {
            std.log.err("gateway connection error: {any}", .{e});
        };
        conn.stream.close();
    }
}

fn handleConn(a: std.mem.Allocator, app: *App, cfg: config.ValidatedConfig, conn: std.net.StreamServer.Connection, token: []const u8) !void {
    const max = cfg.raw.security.max_request_bytes;

    const rid = trace.newRequestId();
    var logger = obs.Logger.fromConfig(cfg);

    var req = http.readRequest(a, conn.stream, max) catch |e| {
        logger.logJson(a, .error, rid.slice(), .{ .error_name = @errorName(e), .context = "gateway.readRequest" });
        const body = try std.fmt.allocPrint(a, "{{\"request_id\":\"{s}\",\"error\":\"{s}\"}}", .{ rid.slice(), @errorName(e) });
        defer a.free(body);
        const hdrs = [_]http.Header{ .{ .name = "x-request-id", .value = rid.slice() } };
        try http.writeJsonWithHeaders(conn.stream, switch (e) {
            error.RequestTooLarge => 413,
            else => 400,
        }, body, &hdrs);
        return;
    };
    defer req.deinit(a);

    logger.logJson(a, .gateway_request, rid.slice(), .{
        .method = req.method,
        .target = req.target,
        .bytes_in = req.raw.len,
    });

    // per-request arena for JSON parsing etc
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ta = arena.allocator();

    var r = routes.handle(ta, app, cfg, req, token, rid.slice()) catch |e| {
        logger.logJson(ta, .error, rid.slice(), .{ .error_name = @errorName(e), .context = "gateway.routes.handle" });
        const body = try std.fmt.allocPrint(ta, "{{\"request_id\":\"{s}\",\"error\":\"{s}\"}}", .{ rid.slice(), @errorName(e) });
        const hdrs = [_]http.Header{ .{ .name = "x-request-id", .value = rid.slice() } };
        try http.writeJsonWithHeaders(conn.stream, 500, body, &hdrs);
        return;
    };
    defer r.deinit(ta);

    const hdrs = [_]http.Header{ .{ .name = "x-request-id", .value = rid.slice() } };
    try http.writeJsonWithHeaders(conn.stream, r.status, r.body, &hdrs);
}
