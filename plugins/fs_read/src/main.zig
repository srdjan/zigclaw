const std = @import("std");
const sdk = @import("plugin_sdk");

pub fn main(init: std.process.Init) !void {
    const a = init.gpa;
    const io = init.io;

    const stdin = std.Io.File.stdin();
    var rbuf: [4096]u8 = undefined;
    var reader = stdin.reader(io, &rbuf);
    const input = try reader.interface.allocRemaining(a, std.Io.Limit.limited(1024 * 1024));
    defer a.free(input);

    var parsed = try std.json.parseFromSlice(std.json.Value, a, input, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const request_id = obj.get("request_id").?.string;
    const args_json = if (obj.get("args_json")) |v| v.string else "{}";

    // args_json is a JSON string; parse it
    var args_parsed = try std.json.parseFromSlice(std.json.Value, a, args_json, .{});
    defer args_parsed.deinit();

    const aobj = args_parsed.value.object;
    const path = if (aobj.get("path")) |v| v.string else "/workspace/README.md";
    const max_bytes: usize = if (aobj.get("max_bytes")) |v| @intCast(v.integer) else 65536;

    var data_json: []u8 = undefined;
    var ok = true;
    var stdout_msg: []const u8 = "";
    const stderr_msg: []const u8 = "";

    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(max_bytes)) catch |e| {
        ok = false;
        data_json = try std.fmt.allocPrint(a, "{{\"error\":\"open failed\"}}", .{});
        defer a.free(data_json);
        const err_msg = try std.fmt.allocPrint(a, "open failed: {any}", .{e});
        defer a.free(err_msg);
        return sdk.writeResp(a, io, request_id, ok, data_json, "", err_msg);
    };
    defer a.free(bytes);

    // base64 encode
    const enc_len = std.base64.standard.Encoder.calcSize(bytes.len);
    const enc = try a.alloc(u8, enc_len);
    defer a.free(enc);
    _ = std.base64.standard.Encoder.encode(enc, bytes);

    data_json = try std.fmt.allocPrint(a, "{{\"content_base64\":\"{s}\"}}", .{enc});
    defer a.free(data_json);

    stdout_msg = "fs_read ok";
    try sdk.writeResp(a, io, request_id, ok, data_json, stdout_msg, stderr_msg);
}
