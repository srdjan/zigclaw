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

pub fn readRequest(a: std.mem.Allocator, io: std.Io, stream: *std.Io.net.Stream, max_bytes: usize) !RequestOwned {
    var buf = std.array_list.Managed(u8).init(a);
    errdefer buf.deinit();

    var rbuf: [4096]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var tmp: [4096]u8 = undefined;
    var header_end: ?usize = null;

    while (header_end == null) {
        const n = try reader.interface.readSliceShort(&tmp);
        if (n == 0) return error.ConnectionClosed;
        if (buf.items.len + n > max_bytes) return error.RequestTooLarge;
        try buf.appendSlice(tmp[0..n]);

        if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |i| {
            header_end = i;
            break;
        }
    }

    const he = header_end.?;
    const after = he + 4;

    // Scan content-length directly from raw bytes - avoids allocating headers twice
    const cl = scanContentLength(buf.items[0..he]);
    while (buf.items.len < after + cl) {
        const n = try reader.interface.readSliceShort(&tmp);
        if (n == 0) return error.ConnectionClosed;
        if (buf.items.len + n > max_bytes) return error.RequestTooLarge;
        try buf.appendSlice(tmp[0..n]);
    }

    const raw = try buf.toOwnedSlice();
    return try parseFromRaw(a, raw);
}

/// Parse an HTTP request from a raw byte buffer. The raw buffer must contain
/// headers terminated by "\r\n\r\n". Caller owns `raw` - it will be stored
/// in the returned RequestOwned and freed on deinit.
pub fn parseFromRaw(a: std.mem.Allocator, raw: []u8) !RequestOwned {
    const he = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.BadRequest;
    const head = raw[0..he];
    const after = he + 4;

    var lines_it = std.mem.splitSequence(u8, head, "\r\n");
    const req_line = lines_it.next() orelse return error.BadRequest;

    const method, const target = try parseRequestLine(req_line);

    var headers_list = std.array_list.Managed(Header).init(a);
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

fn scanContentLength(head: []const u8) usize {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next(); // skip request line
    while (lines.next()) |ln| {
        if (ln.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, ln, ':') orelse continue;
        const name = std.mem.trim(u8, ln[0..colon], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const value = std.mem.trim(u8, ln[colon + 1 ..], " \t");
            return std.fmt.parseInt(usize, value, 10) catch 0;
        }
    }
    return 0;
}

pub fn writeJson(io: std.Io, stream: *std.Io.net.Stream, status_code: u16, body: []const u8) !void {
    return writeJsonWithHeaders(io, stream, status_code, body, &.{});
}

pub fn writeJsonWithHeaders(io: std.Io, stream: *std.Io.net.Stream, status_code: u16, body: []const u8, extra: []const Header) !void {
    var wbuf: [4096]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    try w.interface.print(
        "HTTP/1.1 {d} {s}\r\ncontent-type: application/json\r\ncontent-length: {d}\r\nconnection: close\r\n",
        .{ status_code, reasonPhrase(status_code), body.len },
    );
    for (extra) |h| {
        try w.interface.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try w.interface.writeAll("\r\n");
    try w.interface.writeAll(body);
    try w.interface.flush();
}

pub fn writeText(io: std.Io, stream: *std.Io.net.Stream, status_code: u16, body: []const u8) !void {
    var wbuf: [4096]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    try w.interface.print(
        "HTTP/1.1 {d} {s}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}",
        .{ status_code, reasonPhrase(status_code), body.len, body },
    );
    try w.interface.flush();
}

fn reasonPhrase(code: u16) []const u8 {
    return switch (code) {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        else => "OK",
    };
}
