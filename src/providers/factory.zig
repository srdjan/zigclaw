const std = @import("std");
const config = @import("../config.zig");
const provider = @import("provider.zig");
const openai = @import("openai_compat.zig");
const replay = @import("replay.zig");
const recording = @import("recording.zig");
const reliable = @import("reliable.zig");

pub fn build(a: std.mem.Allocator, cfg: config.ValidatedConfig) !provider.Provider {
    // Base provider
    var base = try buildBase(a, cfg.raw.provider_primary);

    // Wrap in fixtures (replay/record)
    switch (cfg.raw.provider_fixtures.mode) {
        .off => {},
        .replay => {
            const p = try replay.ReplayProvider.init(a, cfg.raw.provider_fixtures.dir);
            base = .{ .replay = p };
        },
        .record => {
            const inner_ptr = try a.create(provider.Provider);
            inner_ptr.* = base;
            const p = try recording.RecordingProvider.init(a, inner_ptr, cfg.raw.provider_fixtures.dir);
            base = .{ .record = p };
        },
    }

    // Wrap reliable retry if enabled
    if (cfg.raw.provider_reliable.retries > 0) {
        const inner_ptr = try a.create(provider.Provider);
        inner_ptr.* = base;
        const p = reliable.ReliableProvider.init(inner_ptr, cfg.raw.provider_reliable.retries, cfg.raw.provider_reliable.backoff_ms);
        base = .{ .reliable = p };
    }

    return base;
}

fn buildBase(a: std.mem.Allocator, p: config.ProviderConfig) !provider.Provider {
    return switch (p.kind) {
        .stub => .{ .stub = .{} },
        .openai_compat => .{ .openai_compat = try openai.OpenAiCompatProvider.init(a, p.base_url, p.api_key, p.api_key_env) },
    };
}
