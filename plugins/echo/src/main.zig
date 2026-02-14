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

    // parse args_json string
    var args_parsed = try std.json.parseFromSlice(std.json.Value, a, args_json, .{});
    defer args_parsed.deinit();
    const aobj = args_parsed.value.object;

    const text = (aobj.get("text") orelse .{ .string = "" }).string;

    const data_json = try std.fmt.allocPrint(a, "{{\"echo\":{s}}}", .{fmtJsonString(text)});
    defer a.free(data_json);

    try sdk.writeResp(a, request_id, true, data_json, "echo ok", "");
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
