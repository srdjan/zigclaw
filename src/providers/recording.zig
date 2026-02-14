const std = @import("std");
const provider = @import("provider.zig");
const fixtures = @import("fixtures.zig");

pub const RecordingProvider = struct {
    inner: *provider.Provider,
    dir: []const u8,

    pub fn init(a: std.mem.Allocator, inner: *provider.Provider, dir: []const u8) !RecordingProvider {
        return .{
            .inner = inner,
            .dir = try a.dupe(u8, dir),
        };
    }

    pub fn deinit(self: *RecordingProvider, a: std.mem.Allocator) void {
        a.free(self.dir);
        self.inner.deinit(a);
        a.destroy(self.inner);
    }

    pub fn chat(self: RecordingProvider, a: std.mem.Allocator, req: provider.ChatRequest) !provider.ChatResponse {
        const resp = try self.inner.chat(a, req);

        // write fixture (best-effort)
        std.fs.cwd().makePath(self.dir) catch {};
        const hash = fixtures.requestHashHexAlloc(a, req) catch "";
        defer if (hash.len > 0) a.free(hash);

        if (hash.len > 0) {
            const path = fixtures.fixturePathAlloc(a, self.dir, hash) catch "";
            defer if (path.len > 0) a.free(path);

            if (path.len > 0) {
                // if exists, do not overwrite
                const file_exists = if (std.fs.cwd().access(path, .{})) |_| true else |_| false;
                if (!file_exists) {
                    var file = std.fs.cwd().createFile(path, .{ .truncate = true }) catch null;
                    if (file) |*f| {
                        defer f.close();
                        const record = try buildFixtureJsonAlloc(a, req, resp.content, req.meta);
                        defer a.free(record);
                        f.writer().writeAll(record) catch {};
                        f.writer().writeAll("\n") catch {};
                    }
                }
            }
        }

        return resp;
    }
};

fn buildFixtureJsonAlloc(a: std.mem.Allocator, req: provider.ChatRequest, content: []const u8, meta: provider.RequestMeta) ![]u8 {
    var stream = std.json.StringifyStream.init(a);
    defer stream.deinit();

    try stream.beginObject();

    if (meta.request_id) |rid| {
        try stream.objectField("request_id"); try stream.write(rid);
    }
    if (meta.prompt_hash) |ph| {
        try stream.objectField("prompt_hash"); try stream.write(ph);
    }

    try stream.objectField("request");
    try stream.beginObject();
    if (req.system) |s| { try stream.objectField("system"); try stream.write(s); }
    try stream.objectField("user"); try stream.write(req.user);
    try stream.objectField("model"); try stream.write(req.model);
    try stream.objectField("temperature"); try stream.write(req.temperature);

    try stream.objectField("memory_context");
    try stream.beginArray();
    for (req.memory_context) |m| {
        try stream.beginObject();
        try stream.objectField("title"); try stream.write(m.title);
        try stream.objectField("snippet"); try stream.write(m.snippet);
        try stream.objectField("score"); try stream.write(m.score);
        try stream.endObject();
    }
    try stream.endArray();

    try stream.endObject(); // request

    try stream.objectField("response");
    try stream.beginObject();
    try stream.objectField("content"); try stream.write(content);
    try stream.endObject();

    try stream.endObject();

    return try stream.toOwnedSlice();
}
