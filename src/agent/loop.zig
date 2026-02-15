const std = @import("std");
const config = @import("../config.zig");
const provider_mod = @import("../providers/provider.zig");
const provider_factory = @import("../providers/factory.zig");
const bundle_mod = @import("bundle.zig");
const obs = @import("../obs/logger.zig");
const trace = @import("../obs/trace.zig");
const tools_runner = @import("../tools/runner.zig");
const manifest_mod = @import("../tools/manifest.zig");

const max_agent_turns: usize = 10;

pub const AgentResult = struct {
    content: []u8,
    turns: usize,

    pub fn deinit(self: *AgentResult, a: std.mem.Allocator) void {
        a.free(self.content);
    }
};

/// CLI entry point: runs the agent loop and prints the result to stdout.
pub fn run(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, message: []const u8) !void {
    const rid = trace.newRequestId(io);

    var result = try runLoop(a, io, cfg, message, rid.slice());
    defer result.deinit(a);

    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.print("request_id={s}\nturns={d}\n{s}\n", .{ rid.slice(), result.turns, result.content });
    try ow.flush();
}

/// Core iterative agent loop. Reusable from both CLI and gateway.
pub fn runLoop(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    message: []const u8,
    request_id: []const u8,
) !AgentResult {
    var logger = obs.Logger.fromConfig(cfg, io);

    var provider = try provider_factory.build(a, cfg);
    defer provider.deinit(a);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ta = arena.allocator();

    var b = try bundle_mod.build(ta, io, cfg, message);
    defer b.deinit(ta);

    logger.logJson(ta, .agent_run, request_id, .{
        .prompt_hash = b.prompt_hash_hex,
        .provider_kind = @tagName(cfg.raw.provider_primary.kind),
        .model = cfg.raw.provider_primary.model,
        .policy_hash = cfg.policy.policyHash(),
    });

    // Build tool definitions from allowed tools in the policy
    const tool_defs = try loadToolDefs(ta, io, cfg);

    // Build initial messages: system + user (with memory folded into system)
    var messages = std.array_list.Managed(provider_mod.Message).init(ta);

    try messages.append(.{ .role = .system, .content = b.system });

    // Fold memory into a separate system-level context if present
    if (b.memory.len > 0) {
        var mem_buf: std.Io.Writer.Allocating = .init(ta);
        defer mem_buf.deinit();
        try mem_buf.writer.writeAll("[Memory context]\n");
        for (b.memory) |m| {
            try mem_buf.writer.print("- {s}: {s}\n", .{ m.title, m.snippet });
        }
        const mem_text = try mem_buf.toOwnedSlice();
        try messages.append(.{ .role = .system, .content = mem_text });
    }

    try messages.append(.{ .role = .user, .content = message });

    // Iterative loop
    var turn: usize = 0;
    while (turn < max_agent_turns) : (turn += 1) {
        logger.logJson(ta, .provider_call, request_id, .{
            .kind = @tagName(cfg.raw.provider_primary.kind),
            .model = cfg.raw.provider_primary.model,
            .status = "start",
            .turn = turn,
        });

        const resp = provider.chat(ta, io, .{
            .messages = messages.items,
            .tools = tool_defs,
            .model = cfg.raw.provider_primary.model,
            .temperature = cfg.raw.provider_primary.temperature,
            .meta = .{ .request_id = request_id, .prompt_hash = b.prompt_hash_hex },
        }) catch |e| {
            logger.logJson(ta, .provider_call, request_id, .{
                .kind = @tagName(cfg.raw.provider_primary.kind),
                .model = cfg.raw.provider_primary.model,
                .status = "error",
                .error_name = @errorName(e),
                .turn = turn,
            });
            return e;
        };

        logger.logJson(ta, .provider_call, request_id, .{
            .kind = @tagName(cfg.raw.provider_primary.kind),
            .model = cfg.raw.provider_primary.model,
            .status = "ok",
            .bytes_out = resp.content.len,
            .tool_calls_count = resp.tool_calls.len,
            .finish_reason = @tagName(resp.finish_reason),
            .turn = turn,
        });

        // If no tool calls, we are done
        if (resp.finish_reason != .tool_calls or resp.tool_calls.len == 0) {
            return .{
                .content = try a.dupe(u8, resp.content),
                .turns = turn + 1,
            };
        }

        // Append the assistant message (with tool_calls, possibly null content)
        try messages.append(.{
            .role = .assistant,
            .content = if (resp.content.len > 0) resp.content else null,
            .tool_calls = resp.tool_calls,
        });

        // Execute each tool call and append results
        for (resp.tool_calls) |tc| {
            logger.logJson(ta, .tool_run, request_id, .{
                .tool = tc.name,
                .tool_call_id = tc.id,
                .turn = turn,
                .status = "start",
            });

            const tool_result = tools_runner.run(ta, io, cfg, request_id, tc.name, tc.arguments) catch |e| {
                // Tool execution failed - send error back to LLM
                const err_msg = try std.fmt.allocPrint(ta, "Tool execution error: {s}", .{@errorName(e)});

                logger.logJson(ta, .tool_run, request_id, .{
                    .tool = tc.name,
                    .tool_call_id = tc.id,
                    .turn = turn,
                    .status = "error",
                    .error_name = @errorName(e),
                });

                try messages.append(.{
                    .role = .tool,
                    .content = err_msg,
                    .tool_call_id = tc.id,
                });
                continue;
            };

            logger.logJson(ta, .tool_run, request_id, .{
                .tool = tc.name,
                .tool_call_id = tc.id,
                .turn = turn,
                .status = "ok",
                .ok = tool_result.ok,
            });

            // Build tool result content from data_json + stdout
            const result_content = if (tool_result.data_json.len > 0)
                tool_result.data_json
            else
                tool_result.stdout;

            try messages.append(.{
                .role = .tool,
                .content = result_content,
                .tool_call_id = tc.id,
            });
        }
    }

    // Exhausted max turns - return whatever content we have from the last response,
    // or a fallback message
    logger.logJson(ta, .agent_run, request_id, .{
        .status = "max_turns_reached",
        .turns = max_agent_turns,
    });

    return .{
        .content = try a.dupe(u8, "Agent reached maximum number of turns without completing."),
        .turns = max_agent_turns,
    };
}

/// Load tool definitions for all tools allowed by the active policy preset.
/// Returns a slice of ToolDef suitable for passing to the provider.
fn loadToolDefs(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig) ![]const provider_mod.ToolDef {
    var defs = std.array_list.Managed(provider_mod.ToolDef).init(a);

    for (cfg.policy.active.tools) |tool_name| {
        const manifest_path = try std.fmt.allocPrint(a, "{s}/{s}.toml", .{ cfg.raw.tools.plugin_dir, tool_name });
        defer a.free(manifest_path);

        var owned = manifest_mod.loadManifest(a, io, manifest_path) catch |e| {
            // Skip tools whose manifests cannot be loaded (log and continue)
            std.log.warn("agent: skipping tool '{s}': manifest load failed: {s}", .{ tool_name, @errorName(e) });
            continue;
        };
        defer owned.deinit(a);

        // Build the JSON schema string for parameters
        var schema_buf: std.Io.Writer.Allocating = .init(a);
        defer schema_buf.deinit();
        var schema_stream: std.json.Stringify = .{ .writer = &schema_buf.writer };
        try owned.manifest.args.writeJson(&schema_stream);
        const params_json = try schema_buf.toOwnedSlice();

        try defs.append(.{
            .name = try a.dupe(u8, owned.manifest.tool_name),
            .description = try a.dupe(u8, owned.manifest.description),
            .parameters_json = params_json,
        });
    }

    return try defs.toOwnedSlice();
}
