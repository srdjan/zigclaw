const std = @import("std");
const App = @import("../app.zig").App;
const config = @import("../config.zig");
const http = @import("http.zig");
const routes = @import("routes.zig");
const token_mod = @import("token.zig");
const trace = @import("../obs/trace.zig");
const obs = @import("../obs/logger.zig");

pub fn start(a: std.mem.Allocator, io: std.Io, app: *App, cfg: config.ValidatedConfig, bind: []const u8, port: u16) !void {
    var t = try token_mod.loadOrCreate(a, io, cfg.raw.security.workspace_root);
    defer t.deinit(a);

    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.print(
        "gateway listening on http://{s}:{d}\nAuthorization: Bearer {s}\nOps UI: http://{s}:{d}/ops?token={s}\n(token stored at {s})\n",
        .{ bind, port, t.token, bind, port, t.token, t.path },
    );
    try ow.flush();

    const ip = try std.Io.net.IpAddress.parse(bind, port);
    var server = try ip.listen(io, .{});

    while (true) {
        var stream = try server.accept(io);
        handleConn(a, io, app, cfg, &stream, t.token) catch |e| {
            std.log.err("gateway connection error: {any}", .{e});
        };
        stream.close(io);
    }
}

fn handleConn(a: std.mem.Allocator, io: std.Io, app: *App, cfg: config.ValidatedConfig, stream: *std.Io.net.Stream, token: []const u8) !void {
    const max = cfg.raw.security.max_request_bytes;

    const rid = trace.newRequestId(io);
    var logger = obs.Logger.fromConfig(cfg, io);

    var req = http.readRequest(a, io, stream, max) catch |e| {
        logger.logJson(a, .err, rid.slice(), .{ .error_name = @errorName(e), .context = "gateway.readRequest" });
        const body = try std.fmt.allocPrint(a, "{{\"request_id\":\"{s}\",\"error\":\"{s}\"}}", .{ rid.slice(), @errorName(e) });
        defer a.free(body);
        const hdrs = [_]http.Header{.{ .name = "x-request-id", .value = rid.slice() }};
        try http.writeJsonWithHeaders(io, stream, switch (e) {
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

    var r = routes.handle(ta, io, app, cfg, req, token, rid.slice()) catch |e| {
        logger.logJson(ta, .err, rid.slice(), .{ .error_name = @errorName(e), .context = "gateway.routes.handle" });
        const body = try std.fmt.allocPrint(ta, "{{\"request_id\":\"{s}\",\"error\":\"{s}\"}}", .{ rid.slice(), @errorName(e) });
        const hdrs = [_]http.Header{.{ .name = "x-request-id", .value = rid.slice() }};
        try http.writeJsonWithHeaders(io, stream, 500, body, &hdrs);
        return;
    };
    defer r.deinit(ta);

    const hdrs = [_]http.Header{.{ .name = "x-request-id", .value = rid.slice() }};
    try http.writeResponseWithHeaders(io, stream, r.status, r.content_type, r.body, &hdrs);
}
