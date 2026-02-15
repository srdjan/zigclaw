const std = @import("std");
const config_mod = @import("config.zig");
const agent_loop = @import("agent/loop.zig");
const tools_runner = @import("tools/runner.zig");
const trace = @import("obs/trace.zig");

pub const App = struct {
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn init(a: std.mem.Allocator, io: std.Io) !App {
        return .{ .allocator = a, .io = io };
    }

    pub fn deinit(self: *App) void {
        _ = self;
    }

    pub fn loadConfig(self: *App, path: []const u8) !config_mod.ValidatedConfig {
        return try config_mod.loadAndValidate(self.allocator, self.io, path);
    }

    pub fn runAgent(self: *App, cfg: config_mod.ValidatedConfig, message: []const u8, opts: agent_loop.RunOptions) !void {
        try agent_loop.run(self.allocator, self.io, cfg, message, opts);
    }

    pub fn runTool(
        self: *App,
        cfg: config_mod.ValidatedConfig,
        tool: []const u8,
        args_json: []const u8,
    ) !tools_runner.ToolRunResult {
        const rid = trace.newRequestId(self.io);
        return try tools_runner.run(self.allocator, self.io, cfg, rid.slice(), tool, args_json, .{});
    }

    pub fn runToolWithRequestId(
        self: *App,
        a: std.mem.Allocator,
        cfg: config_mod.ValidatedConfig,
        request_id: []const u8,
        tool: []const u8,
        args_json: []const u8,
    ) !tools_runner.ToolRunResult {
        return try tools_runner.run(a, self.io, cfg, request_id, tool, args_json, .{});
    }
};
