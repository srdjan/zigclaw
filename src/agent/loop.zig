const std = @import("std");
const config = @import("../config.zig");
const provider_factory = @import("../providers/factory.zig");
const bundle = @import("bundle.zig");
const obs = @import("../obs/logger.zig");
const trace = @import("../obs/trace.zig");

pub fn run(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, message: []const u8) !void {
    const rid = trace.newRequestId(io);
    var logger = obs.Logger.fromConfig(cfg, io);

    var provider = try provider_factory.build(a, cfg);
    defer provider.deinit(a);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ta = arena.allocator();

    var b = try bundle.build(ta, io, cfg, message);
    defer b.deinit(ta);

    logger.logJson(ta, .agent_run, rid.slice(), .{
        .prompt_hash = b.prompt_hash_hex,
        .provider_kind = @tagName(cfg.raw.provider_primary.kind),
        .model = cfg.raw.provider_primary.model,
        .policy_hash = cfg.policy.policyHash(),
    });

    logger.logJson(ta, .provider_call, rid.slice(), .{
        .kind = @tagName(cfg.raw.provider_primary.kind),
        .model = cfg.raw.provider_primary.model,
        .status = "start",
    });

    const resp = provider.chat(ta, io, .{
        .system = b.system,
        .user = message,
        .model = cfg.raw.provider_primary.model,
        .temperature = cfg.raw.provider_primary.temperature,
        .memory_context = b.memory,
        .meta = .{ .request_id = rid.slice(), .prompt_hash = b.prompt_hash_hex },
    }) catch |e| {
        logger.logJson(ta, .provider_call, rid.slice(), .{
            .kind = @tagName(cfg.raw.provider_primary.kind),
            .model = cfg.raw.provider_primary.model,
            .status = "error",
            .error_name = @errorName(e),
        });
        return e;
    };

    logger.logJson(ta, .provider_call, rid.slice(), .{
        .kind = @tagName(cfg.raw.provider_primary.kind),
        .model = cfg.raw.provider_primary.model,
        .status = "ok",
        .bytes_out = resp.content.len,
    });

    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.print("request_id={s}\n{s}\n", .{ rid.slice(), resp.content });
    try ow.flush();
}
