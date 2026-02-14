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

    // parse args_json string
    var args_parsed = try std.json.parseFromSlice(std.json.Value, a, args_json, .{});
    defer args_parsed.deinit();
    const aobj = args_parsed.value.object;

    const text = (aobj.get("text") orelse .{ .string = "" }).string;

    const data_json = try std.fmt.allocPrint(a, "{{\"echo\":{s}}}", .{fmtJsonString(text)});
    defer a.free(data_json);

    try writeResp(a, request_id, true, data_json, "echo ok", "");
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

fn fmtJsonString(s: []const u8) JsonStringFmt {
    return .{ .s = s };
}
const JsonStringFmt = struct {
    s: []const u8,
    pub fn format(self: JsonStringFmt, comptime _: []const u8, _: std.fmt.FormatOptions, w: anytype) !void {
        // emit a JSON string literal with minimal escaping
        try w.writeByte('"');
        for (self.s) |c| {
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
};
