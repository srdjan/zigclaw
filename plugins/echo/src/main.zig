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

    // parse args_json string
    var args_parsed = try std.json.parseFromSlice(std.json.Value, a, args_json, .{});
    defer args_parsed.deinit();
    const aobj = args_parsed.value.object;

    const text = if (aobj.get("text")) |v| v.string else "";

    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    try aw.writer.writeAll("{\"echo\":");
    try writeJsonString(&aw.writer, text);
    try aw.writer.writeAll("}");
    const data_json = try aw.toOwnedSlice();
    defer a.free(data_json);

    try sdk.writeResp(a, io, request_id, true, data_json, "echo ok", "");
}

fn writeJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}
