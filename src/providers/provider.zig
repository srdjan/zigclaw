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

// --- Message types for multi-turn conversations ---

pub const Role = enum { system, user, assistant, tool };

pub const ToolCall = struct {
    id: []const u8,
    name: []const u8,
    arguments: []const u8, // JSON string of tool arguments
};

pub const ToolDef = struct {
    name: []const u8,
    description: []const u8,
    parameters_json: []const u8, // JSON schema string for args
};

pub const Message = struct {
    role: Role,
    content: ?[]const u8 = null,
    tool_calls: []const ToolCall = &.{}, // present on assistant messages requesting tool use
    tool_call_id: ?[]const u8 = null, // present on tool result messages
};

pub const FinishReason = enum { stop, tool_calls, length, unknown };

pub const TokenUsage = struct {
    prompt_tokens: u64 = 0,
    completion_tokens: u64 = 0,
    total_tokens: u64 = 0,
};

// --- Request / Response ---

pub const ChatRequest = struct {
    // Multi-turn: if messages is non-empty, provider uses it directly.
    // Otherwise, provider constructs messages from system/user/memory_context (legacy path).
    messages: []const Message = &.{},
    tools: []const ToolDef = &.{},

    // Legacy single-turn fields (used when messages is empty)
    system: ?[]const u8 = null,
    user: []const u8 = "",
    memory_context: []const MemoryItem = &.{},

    model: []const u8,
    temperature: f64,
    meta: RequestMeta = .{},
};

pub const ChatResponse = struct {
    content: []u8, // empty string when only tool_calls are present
    tool_calls: []ToolCall = &.{}, // non-empty when finish_reason is .tool_calls
    finish_reason: FinishReason = .stop,
    usage: TokenUsage = .{},
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
