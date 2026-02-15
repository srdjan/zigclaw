const std = @import("std");
const provider = @import("provider.zig");
const fixtures = @import("fixtures.zig");

pub const ReplayProvider = struct {
    dir: []const u8,

    pub fn init(a: std.mem.Allocator, dir: []const u8) !ReplayProvider {
        return .{ .dir = try a.dupe(u8, dir) };
    }

    pub fn deinit(self: *ReplayProvider, a: std.mem.Allocator) void {
        a.free(self.dir);
    }

    pub fn chat(self: ReplayProvider, a: std.mem.Allocator, io: std.Io, req: provider.ChatRequest) !provider.ChatResponse {
        const hash = try fixtures.requestHashHexAlloc(a, req);
        defer a.free(hash);

        const path = try fixtures.fixturePathAlloc(a, self.dir, hash);
        defer a.free(path);

        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(4 * 1024 * 1024)) catch return error.FixtureNotFound;
        defer a.free(bytes);

        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const ta = arena.allocator();

        const parsed = std.json.parseFromSlice(std.json.Value, ta, bytes, .{}) catch return error.InvalidJson;
        const root = parsed.value;

        const resp = root.object.get("response") orelse return error.InvalidFixture;
        const content = resp.object.get("content") orelse return error.InvalidFixture;
        if (content != .string) return error.InvalidFixture;

        return .{ .content = try a.dupe(u8, content.string) };
    }
};
