const std = @import("std");
const config = @import("../config.zig");
const provider = @import("provider.zig");
const openai = @import("openai_compat.zig");
const replay = @import("replay.zig");
const capsule_replay = @import("capsule_replay.zig");
const recording = @import("recording.zig");
const reliable = @import("reliable.zig");
const vault_mod = @import("../vault/vault.zig");
const vault_crypto = @import("../vault/crypto.zig");

pub fn build(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig) !provider.Provider {
    // Base provider
    var base = try buildBase(a, io, cfg);

    // Wrap in fixtures (replay/record)
    switch (cfg.raw.provider_fixtures.mode) {
        .off => {},
        .replay => {
            const p = try replay.ReplayProvider.init(a, cfg.raw.provider_fixtures.dir);
            base = .{ .replay = p };
        },
        .capsule_replay => {
            if (cfg.raw.provider_fixtures.capsule_path.len == 0) return error.InvalidCapsuleReplayPath;
            const p = try capsule_replay.CapsuleReplayProvider.init(a, io, cfg.raw.provider_fixtures.capsule_path);
            base = .{ .capsule_replay = p };
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

fn buildBase(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig) !provider.Provider {
    const p = cfg.raw.provider_primary;
    return switch (p.kind) {
        .stub => .{ .stub = .{} },
        .openai_compat => blk: {
            // Resolve API key: inline > vault > env var
            var api_key = p.api_key;
            if (api_key.len == 0 and p.api_key_vault.len > 0) {
                api_key = try resolveVaultKey(a, io, cfg.raw.vault_path, p.api_key_vault);
            }
            break :blk .{ .openai_compat = try openai.OpenAiCompatProvider.init(a, p.base_url, api_key, p.api_key_env) };
        },
    };
}

fn resolveVaultKey(a: std.mem.Allocator, io: std.Io, vault_path: []const u8, key_name: []const u8) ![]const u8 {
    const prompts = @import("../setup/prompts.zig");

    // Read passphrase from stdin
    var pass_buf: [256]u8 = undefined;
    const passphrase = try prompts.readLine(io, "Vault passphrase: ", &pass_buf);
    if (passphrase.len == 0) return error.VaultPassphraseRequired;

    var v = try vault_mod.open(a, io, vault_path, passphrase);
    defer v.deinit();

    const value = v.get(key_name) orelse return error.VaultKeyNotFound;
    return try a.dupe(u8, value);
}
