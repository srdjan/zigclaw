const std = @import("std");
const config = @import("../config.zig");
const memory_mod = @import("../memory/memory.zig");
const prompt = @import("prompt.zig");

pub const Bundle = struct {
    system: []u8,
    user: []const u8,
    memory: []memory_mod.MemoryItem,
    prompt_hash_hex: []u8,
    policy_hash_hex: []const u8,

    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        a.free(self.system);
        memory_mod.freeRecall(a, self.memory);
        a.free(self.prompt_hash_hex);
        _ = self;
    }
};

pub fn build(a: std.mem.Allocator, cfg: config.ValidatedConfig, message: []const u8) !Bundle {
    const sys = try prompt.buildSystemPrompt(a, cfg);

    var mem = try memory_mod.MemoryBackend.fromConfig(a, cfg.raw.memory);
    defer mem.deinit(a);

    const recalled = try mem.recall(a, message, 5);

    const hash_hex = try computePromptHashHex(a, sys, message, recalled);

    return .{
        .system = sys,
        .user = message,
        .memory = recalled,
        .prompt_hash_hex = hash_hex,
        .policy_hash_hex = cfg.policy.policyHash(),
    };
}

fn computePromptHashHex(a: std.mem.Allocator, system: []const u8, user: []const u8, memory: []const memory_mod.MemoryItem) ![]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("system:");
    h.update(system);
    h.update("\nuser:");
    h.update(user);
    h.update("\nmemory:");
    for (memory) |m| {
        h.update("\n- ");
        h.update(m.title);
        h.update(": ");
        h.update(m.snippet);
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);

    var out = try a.alloc(u8, 64);
    const hex = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i*2] = hex[(b >> 4) & 0xF];
        out[i*2 + 1] = hex[b & 0xF];
    }
    return out;
}

pub fn dumpJsonAlloc(a: std.mem.Allocator, b: Bundle) ![]u8 {
    var stream = std.json.StringifyStream.init(a);
    defer stream.deinit();

    try stream.beginObject();
    try stream.objectField("prompt_hash"); try stream.write(b.prompt_hash_hex);
    try stream.objectField("policy_hash"); try stream.write(b.policy_hash_hex);
    try stream.objectField("system"); try stream.write(b.system);
    try stream.objectField("user"); try stream.write(b.user);

    try stream.objectField("memory");
    try stream.beginArray();
    for (b.memory) |m| {
        try stream.beginObject();
        try stream.objectField("title"); try stream.write(m.title);
        try stream.objectField("snippet"); try stream.write(m.snippet);
        try stream.endObject();
    }
    try stream.endArray();

    try stream.endObject();
    return try stream.toOwnedSlice();
}

pub fn dumpTextAlloc(a: std.mem.Allocator, b: Bundle) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    errdefer out.deinit();

    try out.writer().print("prompt_hash: {s}\n", .{b.prompt_hash_hex});
    try out.writer().print("policy_hash: {s}\n", .{b.policy_hash_hex});
    try out.writer().writeAll("\n=== system ===\n");
    try out.writer().writeAll(b.system);
    try out.writer().writeAll("\n=== user ===\n");
    try out.writer().writeAll(b.user);
    try out.writer().writeAll("\n\n=== memory ===\n");
    for (b.memory) |m| {
        try out.writer().print("- {s}: {s}\n", .{m.title, m.snippet});
    }
    return try out.toOwnedSlice();
}
