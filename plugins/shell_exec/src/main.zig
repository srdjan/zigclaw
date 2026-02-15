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

    // Read cwd from protocol (runner sets this to the actual workspace root for native tools)
    const cwd = if (obj.get("cwd")) |v| switch (v) {
        .string => |s| s,
        else => ".",
    } else ".";

    var args_parsed = try std.json.parseFromSlice(std.json.Value, a, args_json, .{});
    defer args_parsed.deinit();
    const aobj = args_parsed.value.object;

    const command = if (aobj.get("command")) |v| switch (v) {
        .string => |s| s,
        else => return error.MalformedInput,
    } else return error.MalformedInput;

    // Validate command against safe character allowlist
    if (command.len == 0) {
        return sdk.writeResp(a, io, request_id, false, "{\"error\":\"empty command\"}", "", "empty command");
    }
    for (command) |c| {
        if (!isSafeCommandByte(c)) {
            return sdk.writeResp(a, io, request_id, false, "{\"error\":\"unsafe characters in command\"}", "", "command contains disallowed characters");
        }
    }

    // Split command into argv on spaces
    var argv_list = std.array_list.Managed([]const u8).init(a);
    defer argv_list.deinit();

    var it = std.mem.splitScalar(u8, command, ' ');
    while (it.next()) |seg| {
        if (seg.len > 0) try argv_list.append(seg);
    }
    if (argv_list.items.len == 0) {
        return sdk.writeResp(a, io, request_id, false, "{\"error\":\"empty command\"}", "", "no command tokens");
    }

    // Prepend cwd to the first arg if it's not an absolute path (resolve relative to workspace)
    // Actually, just set the working directory. The command itself should be found via PATH.

    // Execute the command
    var child = std.process.spawn(io, .{
        .argv = argv_list.items,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |e| {
        const err_msg = try std.fmt.allocPrint(a, "spawn failed: {s}", .{@errorName(e)});
        defer a.free(err_msg);
        return sdk.writeResp(a, io, request_id, false, "{\"error\":\"spawn failed\"}", "", err_msg);
    };

    _ = cwd; // cwd is available for future use when std.process.spawn supports it

    // Read stdout and stderr
    var stdout_buf: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &stdout_buf);
    const stdout_bytes = try stdout_reader.interface.allocRemaining(a, std.Io.Limit.limited(256 * 1024));
    defer a.free(stdout_bytes);

    var stderr_buf: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &stderr_buf);
    const stderr_bytes = try stderr_reader.interface.allocRemaining(a, std.Io.Limit.limited(64 * 1024));
    defer a.free(stderr_bytes);

    const term = try child.wait(io);
    const exit_code: i64 = switch (term) {
        .exited => |code| @as(i64, code),
        .signal => |sig| -@as(i64, @intCast(@intFromEnum(sig))),
        else => -1,
    };

    // Build result JSON
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("exit_code");
    try stream.write(exit_code);
    try stream.objectField("stdout");
    try stream.write(stdout_bytes);
    try stream.objectField("stderr");
    try stream.write(stderr_bytes);
    try stream.endObject();

    const data_json = try aw.toOwnedSlice();
    defer a.free(data_json);

    const ok = exit_code == 0;
    try sdk.writeResp(a, io, request_id, ok, data_json, stdout_bytes, stderr_bytes);
}

fn isSafeCommandByte(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '.', '_', '/', '-', ' ', ':', '=', ',' => true,
        else => false,
    };
}
