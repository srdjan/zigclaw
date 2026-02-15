const std = @import("std");
const sdk = @import("plugin_sdk");

pub fn main(init: std.process.Init) !void {
    const a = init.gpa;
    const io = init.io;

    const stdin = std.Io.File.stdin();
    var rbuf: [4096]u8 = undefined;
    var reader = stdin.reader(io, &rbuf);
    const input = try reader.interface.allocRemaining(a, std.Io.Limit.limited(2 * 1024 * 1024));
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

    const path = if (aobj.get("path")) |v| switch (v) {
        .string => |s| s,
        else => return error.MalformedInput,
    } else return error.MalformedInput;

    const content = if (aobj.get("content")) |v| switch (v) {
        .string => |s| s,
        else => return error.MalformedInput,
    } else return error.MalformedInput;

    // Write the file
    const dir = std.Io.Dir.cwd();
    dir.writeFile(io, .{ .sub_path = path, .data = content }) catch |e| {
        const err_msg = try std.fmt.allocPrint(a, "write failed: {s}", .{@errorName(e)});
        defer a.free(err_msg);
        return sdk.writeResp(a, io, request_id, false, "{\"error\":\"write failed\"}", "", err_msg);
    };

    const data_json = try std.fmt.allocPrint(a, "{{\"bytes_written\":{d}}}", .{content.len});
    defer a.free(data_json);

    try sdk.writeResp(a, io, request_id, true, data_json, "fs_write ok", "");
}
