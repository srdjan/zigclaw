const std = @import("std");
const config_mod = @import("config.zig");
const agent_loop = @import("agent/loop.zig");
const tools_runner = @import("tools/runner.zig");
const trace = @import("obs/trace.zig");

pub const App = struct {
    allocator: std.mem.Allocator,

    pub fn init(a: std.mem.Allocator) !App {
        return .{ .allocator = a };
    }

    pub fn deinit(self: *App) void {
        _ = self;
    }

    pub fn loadConfig(self: *App, path: []const u8) !config_mod.ValidatedConfig {
        _ = self;
        return try config_mod.loadAndValidate(self.allocator, path);
    }

    pub fn runAgent(self: *App, a: std.mem.Allocator, cfg: config_mod.ValidatedConfig, message: []const u8) !void {
        _ = self;
        try agent_loop.run(a, cfg, message);
    }

    pub fn runTool(
        self: *App,
        a: std.mem.Allocator,
        cfg: config_mod.ValidatedConfig,
        tool: []const u8,
        args_json: []const u8,
    ) !tools_runner.ToolRunResult {
        _ = self;
        const rid = trace.newRequestId();
        return try tools_runner.run(a, cfg, rid.slice(), tool, args_json);
    }

    pub fn runToolWithRequestId(
        self: *App,
        a: std.mem.Allocator,
        cfg: config_mod.ValidatedConfig,
        request_id: []const u8,
        tool: []const u8,
        args_json: []const u8,
    ) !tools_runner.ToolRunResult {
        _ = self;
        return try tools_runner.run(a, cfg, request_id, tool, args_json);
    }
};
