const std = @import("std");
const sdk = @import("plugin_sdk");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const stdin: std.Io.File = .{ .handle = 0, .flags = .{ .nonblocking = false } };
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
    const stderr_msg: []const u8 = "";

    const file = std.fs.cwd().openFile(path, .{}) catch |e| {
        ok = false;
        data_json = try std.fmt.allocPrint(a, "{{\"error\":\"open failed\"}}", .{});
        defer a.free(data_json);
        const err_msg = try std.fmt.allocPrint(a, "open failed: {any}", .{e});
        defer a.free(err_msg);
        return sdk.writeResp(a, request_id, ok, data_json, "", err_msg);
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(a, max_bytes);
    defer a.free(bytes);

    // base64 encode
    const enc_len = std.base64.standard.Encoder.calcSize(bytes.len);
    const enc = try a.alloc(u8, enc_len);
    defer a.free(enc);
    _ = std.base64.standard.Encoder.encode(enc, bytes);

    data_json = try std.fmt.allocPrint(a, "{{\"content_base64\":\"{s}\"}}", .{enc});
    defer a.free(data_json);

    stdout_msg = "fs_read ok";
    try sdk.writeResp(a, request_id, ok, data_json, stdout_msg, stderr_msg);
}
