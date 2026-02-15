const std = @import("std");

pub fn writeResp(
    a: std.mem.Allocator,
    io: std.Io,
    request_id: []const u8,
    ok: bool,
    data_json: []const u8,
    stdout_msg: []const u8,
    stderr_msg: []const u8,
) !void {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("protocol_version");
    try stream.write(@as(u32, 0));
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("ok");
    try stream.write(ok);
    try stream.objectField("data_json");
    try stream.write(data_json);
    try stream.objectField("stdout");
    try stream.write(stdout_msg);
    try stream.objectField("stderr");
    try stream.write(stderr_msg);
    try stream.endObject();

    const out = try aw.toOwnedSlice();
    defer a.free(out);

    const stdout = std.Io.File.stdout();
    var wbuf: [4096]u8 = undefined;
    var writer = stdout.writer(io, &wbuf);
    try writer.interface.writeAll(out);
    try writer.flush();
}
