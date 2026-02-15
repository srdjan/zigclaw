const std = @import("std");

const openai = @import("openai_compat.zig");
const replay = @import("replay.zig");
const recording = @import("recording.zig");
const reliable = @import("reliable.zig");
const recall = @import("../memory/recall.zig");

pub const Provider = union(enum) {
    stub: StubProvider,
    openai_compat: openai.OpenAiCompatProvider,
    replay: replay.ReplayProvider,
    record: recording.RecordingProvider,
    reliable: reliable.ReliableProvider,

    pub fn deinit(self: *Provider, a: std.mem.Allocator) void {
        switch (self.*) {
            .stub => {},
            .openai_compat => |*p| p.deinit(a),
            .replay => |*p| p.deinit(a),
            .record => |*p| p.deinit(a),
            .reliable => |*p| p.deinit(a),
        }
    }

    pub fn chat(self: Provider, a: std.mem.Allocator, io: std.Io, req: ChatRequest) !ChatResponse {
        return switch (self) {
            .stub => |p| p.chat(a, io, req),
            .openai_compat => |p| p.chat(a, io, req),
            .replay => |p| p.chat(a, io, req),
            .record => |p| p.chat(a, io, req),
            .reliable => |p| p.chat(a, io, req),
        };
    }
};

pub const MemoryItem = recall.MemoryItem;

pub const RequestMeta = struct {
    request_id: ?[]const u8 = null,
    prompt_hash: ?[]const u8 = null,
};

pub const ChatRequest = struct {
    system: ?[]const u8,
    user: []const u8,
    model: []const u8,
    temperature: f64,
    memory_context: []const MemoryItem,
    meta: RequestMeta = .{},
};

pub const ChatResponse = struct {
    content: []u8,
};

// For fixtures writing without owning new allocations
pub const ChatResponseView = struct {
    content: []const u8,
};

pub const StubProvider = struct {
    pub fn chat(_: StubProvider, a: std.mem.Allocator, _: std.Io, req: ChatRequest) !ChatResponse {
        // Deterministic scaffold response (helps tests)
        const mem_n = req.memory_context.len;
        const sys = req.system orelse "";
        const out = try std.fmt.allocPrint(a,
            \\[stub provider]
            \\model={s} temp={d}
            \\system={s}
            \\memory_items={d}
            \\user={s}
        , .{ req.model, req.temperature, sys, mem_n, req.user });
        return .{ .content = out };
    }
};
