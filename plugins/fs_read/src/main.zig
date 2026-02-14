const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const stdin = std.io.getStdIn();
    const input = try stdin.reader().readAllAlloc(a, 1024 * 1024);
    defer a.free(input);

    var parsed = try std.json.parseFromSlice(std.json.Value, a, input, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const request_id = obj.get("request_id").?.string;
    const args_json = (obj.get("args_json") orelse .{ .string = "{}" }).string;

    // args_json is a JSON string; parse it
    var args_parsed = try std.json.parseFromSlice(std.json.Value, a, args_json, .{});
    defer args_parsed.deinit();

    const aobj = args_parsed.value.object;
    const path = (aobj.get("path") orelse .{ .string = "/workspace/README.md" }).string;
    const max_bytes = @as(usize, @intCast((aobj.get("max_bytes") orelse .{ .integer = 65536 }).integer));

    var data_json: []u8 = undefined;
    var ok = true;
    var stdout_msg: []const u8 = "";
    var stderr_msg: []const u8 = "";

    const file = std.fs.cwd().openFile(path, .{}) catch |e| {
        ok = false;
        stderr_msg = try std.fmt.allocPrint(a, "open failed: {any}", .{e});
        data_json = try std.fmt.allocPrint(a, "{{\"error\":\"open failed\"}}", .{});
        defer a.free(stderr_msg);
        return writeResp(a, request_id, ok, data_json, "", stderr_msg);
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(a, max_bytes);
    defer a.free(bytes);

    // base64 encode
    const enc_len = std.base64.standard.Encoder.calcSize(bytes.len);
    var enc = try a.alloc(u8, enc_len);
    defer a.free(enc);
    _ = std.base64.standard.Encoder.encode(enc, bytes);

    data_json = try std.fmt.allocPrint(a, "{{\"content_base64\":\"{s}\"}}", .{enc});
    defer a.free(data_json);

    stdout_msg = "fs_read ok";
    try writeResp(a, request_id, ok, data_json, stdout_msg, stderr_msg);
}

fn writeResp(
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
    try stream.objectField("protocol_version"); try stream.write(@as(u32, 0));
    try stream.objectField("request_id"); try stream.write(request_id);
    try stream.objectField("ok"); try stream.write(ok);
    try stream.objectField("data_json"); try stream.write(data_json);
    try stream.objectField("stdout"); try stream.write(stdout_msg);
    try stream.objectField("stderr"); try stream.write(stderr_msg);
    try stream.endObject();

    const out = try stream.toOwnedSlice();
    defer a.free(out);

    try std.io.getStdOut().writer().writeAll(out);
}
