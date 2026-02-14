const std = @import("std");

pub fn writeResp(
    a: std.mem.Allocator,
    request_id: []const u8,
    ok: bool,
    data_json: []const u8,
    stdout_msg: []const u8,
    stderr_msg: []const u8,
) !void {
    var stream = std.json.StringifyStream.init(a);
    defer stream.deinit();

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

    const out = try stream.toOwnedSlice();
    defer a.free(out);

    const stdout: std.Io.File = .{ .handle = 1, .flags = .{ .nonblocking = false } };
    try stdout.writer().writeAll(out);
}
