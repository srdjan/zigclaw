const std = @import("std");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const RequestOwned = struct {
    raw: []u8,
    method: []const u8,
    target: []const u8,
    headers: []Header,
    body: []const u8,

    pub fn deinit(self: *RequestOwned, a: std.mem.Allocator) void {
        a.free(self.headers);
        a.free(self.raw);
    }

    pub fn header(self: RequestOwned, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return std.mem.trim(u8, h.value, " \t");
        }
        return null;
    }

    pub fn contentLength(self: RequestOwned) usize {
        if (self.header("content-length")) |v| {
            return std.fmt.parseInt(usize, std.mem.trim(u8, v, " \t"), 10) catch 0;
        }
        return 0;
    }
};

pub fn readRequest(a: std.mem.Allocator, stream: anytype, max_bytes: usize) !RequestOwned {
    var buf = std.ArrayList(u8).init(a);
    errdefer buf.deinit();

    var tmp: [4096]u8 = undefined;
    var header_end: ?usize = null;

    while (header_end == null) {
        const n = try stream.read(&tmp);
        if (n == 0) return error.ConnectionClosed;
        if (buf.items.len + n > max_bytes) return error.RequestTooLarge;
        try buf.appendSlice(tmp[0..n]);

        if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |i| {
            header_end = i;
            break;
        }
    }

    const he = header_end.?;
    const head = buf.items[0..he];
    const after = he + 4;

    var lines_it = std.mem.splitSequence(u8, head, "\r\n");
    const req_line = lines_it.next() orelse return error.BadRequest;
    const method, const target = try parseRequestLine(req_line);

    var headers_list = std.ArrayList(Header).init(a);
    errdefer headers_list.deinit();

    while (lines_it.next()) |ln| {
        if (ln.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, ln, ':') orelse continue;
        const name = std.mem.trim(u8, ln[0..colon], " \t");
        const value = std.mem.trim(u8, ln[colon+1..], " \t");
        try headers_list.append(.{ .name = name, .value = value });
    }

    const headers = try headers_list.toOwnedSlice();
    errdefer a.free(headers);

    const cl = getContentLength(headers);
    while (buf.items.len < after + cl) {
        const n = try stream.read(&tmp);
        if (n == 0) return error.ConnectionClosed;
        if (buf.items.len + n > max_bytes) return error.RequestTooLarge;
        try buf.appendSlice(tmp[0..n]);
    }

    const raw = try buf.toOwnedSlice();
    return try parseFromRaw(a, raw);
}

fn parseFromRaw(a: std.mem.Allocator, raw: []u8) !RequestOwned {
    const he = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.BadRequest;
    const head = raw[0..he];
    const after = he + 4;

    var lines_it = std.mem.splitSequence(u8, head, "\r\n");
    const req_line = lines_it.next() orelse return error.BadRequest;

    const method, const target = try parseRequestLine(req_line);

    var headers_list = std.ArrayList(Header).init(a);
    errdefer headers_list.deinit();

    while (lines_it.next()) |ln| {
        if (ln.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, ln, ':') orelse continue;
        const name = std.mem.trim(u8, ln[0..colon], " \t");
        const value = std.mem.trim(u8, ln[colon+1..], " \t");
        try headers_list.append(.{ .name = name, .value = value });
    }

    const headers = try headers_list.toOwnedSlice();
    const cl = getContentLength(headers);
    const body = raw[after .. @min(raw.len, after + cl)];

    return .{
        .raw = raw,
        .method = method,
        .target = target,
        .headers = headers,
        .body = body,
    };
}

fn parseRequestLine(line: []const u8) !struct { []const u8, []const u8 } {
    var it = std.mem.splitScalar(u8, line, ' ');
    const method = it.next() orelse return error.BadRequest;
    const target = it.next() orelse return error.BadRequest;
    _ = it.next() orelse return error.BadRequest; // HTTP/1.1
    return .{ method, target };
}

fn getContentLength(headers: []const Header) usize {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) {
            return std.fmt.parseInt(usize, std.mem.trim(u8, h.value, " \t"), 10) catch 0;
        }
    }
    return 0;
}

pub fn writeJson(stream: anytype, status_code: u16, body: []const u8) !void {
    return writeJsonWithHeaders(stream, status_code, body, &.{});
}

pub fn writeJsonWithHeaders(stream: anytype, status_code: u16, body: []const u8, extra: []const Header) !void {
    var w = stream.writer();
    try w.print(
        "HTTP/1.1 {d} {s}\r\ncontent-type: application/json\r\ncontent-length: {d}\r\nconnection: close\r\n",
        .{ status_code, reasonPhrase(status_code), body.len },
    );
    for (extra) |h| {
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try w.writeAll("\r\n");
    try w.writeAll(body);
}

pub fn writeText(stream: anytype, status_code: u16, body: []const u8) !void {
    try stream.writer().print(
        "HTTP/1.1 {d} {s}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}",
        .{ status_code, reasonPhrase(status_code), body.len, body },
    );
}

fn reasonPhrase(code: u16) []const u8 {
    return switch (code) {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        else => "OK",
    };
}
