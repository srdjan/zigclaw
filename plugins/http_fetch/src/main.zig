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
    const request_id = if (obj.get("request_id")) |v| switch (v) {
        .string => |s| s,
        else => return error.MalformedInput,
    } else return error.MalformedInput;

    const args_json = if (obj.get("args_json")) |v| switch (v) {
        .string => |s| s,
        else => "{}",
    } else "{}";

    var args_parsed = try std.json.parseFromSlice(std.json.Value, a, args_json, .{});
    defer args_parsed.deinit();
    const aobj = args_parsed.value.object;

    const url = if (aobj.get("url")) |v| switch (v) {
        .string => |s| s,
        else => return error.MalformedInput,
    } else return error.MalformedInput;

    const method = if (aobj.get("method")) |v| switch (v) {
        .string => |s| s,
        else => "GET",
    } else "GET";

    // Validate URL scheme
    if (!std.mem.startsWith(u8, url, "http://") and !std.mem.startsWith(u8, url, "https://")) {
        return sdk.writeResp(a, io, request_id, false, "{\"error\":\"invalid URL scheme\"}", "", "only http:// and https:// URLs are allowed");
    }

    // Build curl command
    var argv = std.array_list.Managed([]const u8).init(a);
    defer argv.deinit();

    try argv.append("curl");
    try argv.append("-s");
    try argv.append("-S");
    try argv.append("-X");
    try argv.append(method);
    try argv.append("-w");
    try argv.append("\n%{http_code}");
    try argv.append("--max-time");
    try argv.append("25");
    try argv.append(url);

    var child = std.process.spawn(io, .{
        .argv = argv.items,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |e| {
        const err_msg = try std.fmt.allocPrint(a, "curl spawn failed: {s}", .{@errorName(e)});
        defer a.free(err_msg);
        return sdk.writeResp(a, io, request_id, false, "{\"error\":\"curl failed\"}", "", err_msg);
    };

    var stdout_buf: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &stdout_buf);
    const stdout_bytes = try stdout_reader.interface.allocRemaining(a, std.Io.Limit.limited(256 * 1024));
    defer a.free(stdout_bytes);

    var stderr_buf: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &stderr_buf);
    const stderr_bytes = try stderr_reader.interface.allocRemaining(a, std.Io.Limit.limited(64 * 1024));
    defer a.free(stderr_bytes);

    _ = try child.wait(io);

    // curl -w "\n%{http_code}" appends the status code on the last line
    // Split stdout into body and status code
    var body: []const u8 = stdout_bytes;
    var status_code: []const u8 = "0";

    if (std.mem.lastIndexOfScalar(u8, stdout_bytes, '\n')) |last_nl| {
        body = stdout_bytes[0..last_nl];
        status_code = stdout_bytes[last_nl + 1 ..];
    }

    // Build result JSON
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("status_code");
    try stream.write(status_code);
    try stream.objectField("body");
    try stream.write(body);
    try stream.objectField("url");
    try stream.write(url);
    try stream.objectField("method");
    try stream.write(method);
    try stream.endObject();

    const data_json = try aw.toOwnedSlice();
    defer a.free(data_json);

    try sdk.writeResp(a, io, request_id, true, data_json, body, stderr_bytes);
}
