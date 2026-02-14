const std = @import("std");
const policy = @import("../policy.zig");

pub const ProtocolVersion: u32 = 0;

pub const ToolRequest = struct {
    protocol_version: u32 = ProtocolVersion,
    request_id: []const u8,
    tool: []const u8,
    args_json: []const u8,
    cwd: []const u8,
    mounts: []const policy.Mount,
};

pub const ToolResponse = struct {
    protocol_version: u32 = ProtocolVersion,
    request_id: []const u8,
    ok: bool,
    data_json: []const u8,
    stdout: []const u8,
    stderr: []const u8,
};

pub fn encodeRequest(a: std.mem.Allocator, req: ToolRequest) ![]u8 {
    var stream = std.json.StringifyStream.init(a);
    defer stream.deinit();

    try stream.beginObject();
    try stream.objectField("protocol_version"); try stream.write(req.protocol_version);
    try stream.objectField("request_id"); try stream.write(req.request_id);
    try stream.objectField("tool"); try stream.write(req.tool);
    try stream.objectField("args_json"); try stream.write(req.args_json);
    try stream.objectField("cwd"); try stream.write(req.cwd);

    try stream.objectField("mounts");
    try stream.beginArray();
    for (req.mounts) |m| {
        try stream.beginObject();
        try stream.objectField("host_path"); try stream.write(m.host_path);
        try stream.objectField("guest_path"); try stream.write(m.guest_path);
        try stream.objectField("read_only"); try stream.write(m.read_only);
        try stream.endObject();
    }
    try stream.endArray();

    try stream.endObject();
    return try stream.toOwnedSlice();
}

pub fn decodeResponse(a: std.mem.Allocator, bytes: []const u8) !ToolResponseOwned {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
    defer parsed.deinit();

    const v = parsed.value;
    const obj = v.object;

    const req_id = try a.dupe(u8, obj.get("request_id").?.string);
    const data = try a.dupe(u8, (obj.get("data_json") orelse .{ .string = "" }).string);
    const out = try a.dupe(u8, (obj.get("stdout") orelse .{ .string = "" }).string);
    const err = try a.dupe(u8, (obj.get("stderr") orelse .{ .string = "" }).string);

    const ok = obj.get("ok").?.bool;
    const pv = @as(u32, @intCast(obj.get("protocol_version").?.integer));

    return .{
        .response = .{
            .protocol_version = pv,
            .request_id = req_id,
            .ok = ok,
            .data_json = data,
            .stdout = out,
            .stderr = err,
        },
    };
}

pub const ToolResponseOwned = struct {
    response: ToolResponse,

    pub fn deinit(self: *ToolResponseOwned, a: std.mem.Allocator) void {
        a.free(self.response.request_id);
        a.free(self.response.data_json);
        a.free(self.response.stdout);
        a.free(self.response.stderr);
    }
};
