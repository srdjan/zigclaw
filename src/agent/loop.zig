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

pub const RunOptions = struct {
    verbose: bool = false,
    interactive: bool = false,
};

pub const AgentResult = struct {
    content: []u8,
    turns: usize,

    pub fn deinit(self: *AgentResult, a: std.mem.Allocator) void {
        a.free(self.content);
    }
};

/// CLI entry point: runs the agent loop and prints the result to stdout.
pub fn run(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, message: []const u8, opts: RunOptions) !void {
    if (opts.interactive) {
        return runInteractive(a, io, cfg, opts);
    }

    const rid = trace.newRequestId(io);

    var result = try runLoop(a, io, cfg, message, rid.slice(), opts);
    defer result.deinit(a);

    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.print("request_id={s}\nturns={d}\n{s}\n", .{ rid.slice(), result.turns, result.content });
    try ow.flush();
}

/// Interactive REPL mode: reads lines from stdin, runs the agent loop for each.
fn runInteractive(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, opts: RunOptions) !void {
    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.writeAll("zigclaw interactive mode. Type a message, or 'quit' to exit.\n");
    try ow.flush();

    const stdin = std.Io.File.stdin();
    var rbuf: [4096]u8 = undefined;
    var reader = stdin.reader(io, &rbuf);

    while (true) {
        try ow.interface.writeAll("> ");
        try ow.flush();

        const line = reader.interface.takeDelimiter('\n') catch |e| switch (e) {
            error.StreamTooLong => {
                _ = reader.interface.discardDelimiterInclusive('\n') catch return;
                try ow.interface.writeAll("(input too long, try again)\n");
                try ow.flush();
                continue;
            },
            error.ReadFailed => return,
        };
        if (line == null) return; // EOF

        const msg = std.mem.trim(u8, line.?, " \t\r\n");
        if (msg.len == 0) continue;
        if (std.mem.eql(u8, msg, "quit") or std.mem.eql(u8, msg, "exit")) return;

        const rid = trace.newRequestId(io);
        var result = runLoop(a, io, cfg, msg, rid.slice(), opts) catch |e| {
            var ebuf: [4096]u8 = undefined;
            var ew = std.Io.File.stderr().writer(io, &ebuf);
            try ew.interface.print("error: {s}\n", .{@errorName(e)});
            try ew.flush();
            continue;
        };
        defer result.deinit(a);

        try ow.interface.print("{s}\n", .{result.content});
        try ow.flush();
    }
}

/// Core iterative agent loop. Reusable from both CLI and gateway.
pub fn runLoop(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    message: []const u8,
    request_id: []const u8,
    opts: RunOptions,
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

    if (opts.verbose) {
        verboseLog(io, "[verbose] request_id={s} model={s} tools={d} memory_items={d}\n", .{
            request_id, cfg.raw.provider_primary.model, tool_defs.len, b.memory.len,
        });
        verboseLog(io, "[verbose] system prompt ({d} bytes)\n", .{b.system.len});
    }

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
            .prompt_tokens = resp.usage.prompt_tokens,
            .completion_tokens = resp.usage.completion_tokens,
            .total_tokens = resp.usage.total_tokens,
        });

        if (opts.verbose) {
            verboseLog(io, "[verbose] turn={d} finish_reason={s} content_bytes={d} tool_calls={d} tokens={d}/{d}/{d}\n", .{
                turn, @tagName(resp.finish_reason), resp.content.len, resp.tool_calls.len,
                resp.usage.prompt_tokens, resp.usage.completion_tokens, resp.usage.total_tokens,
            });
            if (resp.content.len > 0) {
                verboseLog(io, "[verbose] assistant: {s}\n", .{resp.content[0..@min(resp.content.len, 500)]});
            }
            for (resp.tool_calls) |tc| {
                verboseLog(io, "[verbose] tool_call: {s}({s}) id={s}\n", .{ tc.name, tc.arguments[0..@min(tc.arguments.len, 200)], tc.id });
            }
        }

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

            if (opts.verbose) {
                const preview = if (tool_result.data_json.len > 0)
                    tool_result.data_json[0..@min(tool_result.data_json.len, 300)]
                else
                    tool_result.stdout[0..@min(tool_result.stdout.len, 300)];
                verboseLog(io, "[verbose] tool_result: {s} ok={s} preview={s}\n", .{
                    tc.name, if (tool_result.ok) "true" else "false", preview,
                });
            }

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

/// Write a formatted line to stderr (best-effort, for --verbose output).
fn verboseLog(io: std.Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    w.interface.print(fmt, args) catch {};
    w.flush() catch {};
}
