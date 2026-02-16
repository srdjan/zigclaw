const std = @import("std");
const config = @import("../config.zig");
const policy_mod = @import("../policy.zig");
const provider_mod = @import("../providers/provider.zig");
const provider_factory = @import("../providers/factory.zig");
const bundle_mod = @import("bundle.zig");
const obs = @import("../obs/logger.zig");
const hash_mod = @import("../obs/hash.zig");
const trace = @import("../obs/trace.zig");
const decision_log = @import("../decision_log.zig");
const tools_runner = @import("../tools/runner.zig");
const tools_cache = @import("../tools/cache.zig");
const manifest_mod = @import("../tools/manifest.zig");
const token_mod = @import("../policy/token.zig");
const att_ledger = @import("../attestation/ledger.zig");
const att_receipt = @import("../attestation/receipt.zig");
const replay_recorder = @import("../replay/recorder.zig");

const max_agent_turns: usize = 10;
const default_max_delegate_depth: usize = 3;
const delegate_tool_name = "delegate_agent";
const delegate_tool_description = "Delegate a sub-task to another configured agent.";

pub const CancelCheck = struct {
    ctx: ?*anyopaque,
    func: *const fn (ctx: ?*anyopaque) anyerror!bool,
};

pub const RunOptions = struct {
    verbose: bool = false,
    interactive: bool = false,
    agent_id: ?[]const u8 = null,
    delegate_depth: usize = 0,
    max_delegate_depth: usize = default_max_delegate_depth,
    parent_token: ?*const token_mod.CapabilityToken = null,
    cancel_check: ?CancelCheck = null,
};

const ActiveAgent = struct {
    id: []const u8,
    profile: ?config.AgentProfileConfig,
};

pub const AgentResult = struct {
    content: []u8,
    turns: usize,
    attestation: ?Attestation = null,

    pub fn deinit(self: *AgentResult, a: std.mem.Allocator) void {
        a.free(self.content);
    }
};

pub const Attestation = struct {
    merkle_root_hex: [64]u8,
    event_count: usize,
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
) anyerror!AgentResult {
    if (try cancelRequested(opts)) return error.Canceled;
    const ts_start_ms = decision_log.nowUnixMs(io);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ta = arena.allocator();

    const active_agent = try resolveActiveAgent(ta, cfg, opts.agent_id);
    const run_cfg = try cfgForAgent(ta, cfg, active_agent, opts.parent_token);

    var logger = obs.Logger.fromConfig(run_cfg, io);
    const decisions = decision_log.Logger.fromConfig(run_cfg, io);
    const ledger_enabled = opts.delegate_depth == 0;
    var recorder = replay_recorder.TraceRecorder.init(
        a,
        io,
        run_cfg.raw.security.workspace_root,
        request_id,
        opts.delegate_depth == 0,
    );
    defer recorder.deinit();

    var ledger = att_ledger.MerkleTree.init(a);
    defer ledger.deinit();
    const ledger_ptr: ?*att_ledger.MerkleTree = if (ledger_enabled) &ledger else null;

    var tool_args_hashes = std.array_list.Managed([]const u8).init(a);
    defer {
        for (tool_args_hashes.items) |h| a.free(h);
        tool_args_hashes.deinit();
    }

    var tool_output_hashes = std.array_list.Managed([]const u8).init(a);
    defer {
        for (tool_output_hashes.items) |h| a.free(h);
        tool_output_hashes.deinit();
    }

    var cache = tools_cache.ToolCache.init(ta, io, run_cfg.raw.security.workspace_root);
    defer cache.deinit();

    var b = try bundle_mod.build(ta, io, run_cfg, message);
    defer b.deinit(ta);

    recorder.record(.run_start, 0, .{
        .agent_id = active_agent.id,
        .message = message,
        .delegate_depth = opts.delegate_depth,
    }) catch {};

    decisions.logAndRecord(ta, .{
        .ts_unix_ms = decision_log.nowUnixMs(io),
        .request_id = request_id,
        .prompt_hash = b.prompt_hash_hex,
        .decision = "memory.backend",
        .subject = @tagName(run_cfg.raw.memory.backend),
        .allowed = true,
        .reason = if (run_cfg.raw.memory.backend == .sqlite)
            "allowed with scaffold fallback to markdown"
        else
            "allowed by memory backend config",
        .policy_hash = run_cfg.policy.policyHash(),
    }, ledger_ptr);
    decisions.logAndRecord(ta, .{
        .ts_unix_ms = decision_log.nowUnixMs(io),
        .request_id = request_id,
        .prompt_hash = b.prompt_hash_hex,
        .decision = "memory.recall",
        .subject = run_cfg.raw.memory.root,
        .allowed = true,
        .reason = "memory recall executed",
        .policy_hash = run_cfg.policy.policyHash(),
    }, ledger_ptr);
    recorder.record(.memory_recall, 0, .{
        .memory_root = run_cfg.raw.memory.root,
    }) catch {};

    const provider_kind = @tagName(run_cfg.raw.provider_primary.kind);
    const provider_requires_network = run_cfg.raw.provider_primary.kind == .openai_compat;
    const provider_network_allowed = !provider_requires_network or run_cfg.policy.active.allow_network;
    decisions.logAndRecord(ta, .{
        .ts_unix_ms = decision_log.nowUnixMs(io),
        .request_id = request_id,
        .prompt_hash = b.prompt_hash_hex,
        .decision = "provider.network",
        .subject = provider_kind,
        .allowed = provider_network_allowed,
        .reason = if (provider_requires_network)
            (if (provider_network_allowed) "allowed: preset permits provider network access" else "denied: preset disallows provider network access")
        else
            "allowed: provider does not require network",
        .policy_hash = run_cfg.policy.policyHash(),
    }, ledger_ptr);
    recorder.record(.policy_decision, 0, .{
        .decision = "provider.network",
        .allowed = provider_network_allowed,
    }) catch {};
    if (!provider_network_allowed) return error.ProviderNetworkNotAllowed;

    decisions.logAndRecord(ta, .{
        .ts_unix_ms = decision_log.nowUnixMs(io),
        .request_id = request_id,
        .prompt_hash = b.prompt_hash_hex,
        .decision = "provider.select",
        .subject = run_cfg.raw.provider_primary.model,
        .allowed = true,
        .reason = "provider/model selected for run",
        .policy_hash = run_cfg.policy.policyHash(),
    }, ledger_ptr);

    if (run_cfg.raw.provider_fixtures.mode != .off) {
        decisions.logAndRecord(ta, .{
            .ts_unix_ms = decision_log.nowUnixMs(io),
            .request_id = request_id,
            .prompt_hash = b.prompt_hash_hex,
            .decision = "provider.fixtures",
            .subject = @tagName(run_cfg.raw.provider_fixtures.mode),
            .allowed = true,
            .reason = "fixtures wrapper enabled",
            .policy_hash = run_cfg.policy.policyHash(),
        }, ledger_ptr);
    }

    if (run_cfg.raw.provider_reliable.retries > 0) {
        decisions.logAndRecord(ta, .{
            .ts_unix_ms = decision_log.nowUnixMs(io),
            .request_id = request_id,
            .prompt_hash = b.prompt_hash_hex,
            .decision = "provider.reliable",
            .subject = run_cfg.raw.provider_primary.model,
            .allowed = true,
            .reason = "reliable retry wrapper enabled",
            .policy_hash = run_cfg.policy.policyHash(),
        }, ledger_ptr);
    }

    var provider = try provider_factory.build(a, io, run_cfg);
    defer provider.deinit(a);

    logger.logJson(ta, .agent_run, request_id, .{
        .prompt_hash = b.prompt_hash_hex,
        .provider_kind = @tagName(run_cfg.raw.provider_primary.kind),
        .model = run_cfg.raw.provider_primary.model,
        .policy_hash = run_cfg.policy.policyHash(),
        .agent_id = active_agent.id,
        .delegate_depth = opts.delegate_depth,
    });

    // Build tool definitions from allowed tools in this agent's policy.
    const delegate_to = if (active_agent.profile) |p| p.delegate_to else &.{};
    const tool_defs = try loadToolDefs(ta, io, run_cfg, delegate_to);

    if (opts.verbose) {
        verboseLog(io, "[verbose] request_id={s} model={s} tools={d} memory_items={d}\n", .{
            request_id, run_cfg.raw.provider_primary.model, tool_defs.len, b.memory.len,
        });
        verboseLog(io, "[verbose] agent={s} system prompt ({d} bytes)\n", .{ active_agent.id, b.system.len });
    }

    // Build initial messages: system + user (with memory folded into system)
    var messages = std.array_list.Managed(provider_mod.Message).init(ta);

    try messages.append(.{ .role = .system, .content = b.system });

    if (active_agent.profile) |p| {
        if (p.system_prompt.len > 0) {
            try messages.append(.{ .role = .system, .content = p.system_prompt });
        }
    }

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
        if (opts.parent_token) |parent_token| {
            const now_ms = decision_log.nowUnixMs(io);

            if (parent_token.isExpired(now_ms)) {
                decisions.logAndRecord(ta, .{
                    .ts_unix_ms = now_ms,
                    .request_id = request_id,
                    .prompt_hash = b.prompt_hash_hex,
                    .decision = "delegation.token.expired",
                    .subject = active_agent.id,
                    .allowed = false,
                    .reason = "denied: delegation token expired",
                    .policy_hash = run_cfg.policy.policyHash(),
                }, ledger_ptr);
                logger.logJson(ta, .agent_run, request_id, .{
                    .status = "delegation_token_expired",
                    .turn = turn,
                    .agent_id = active_agent.id,
                    .token_hash = parent_token.token_hash[0..],
                });
                return error.DelegateTokenExpired;
            }

            if (!parent_token.isWithinTurnLimit(turn)) {
                decisions.logAndRecord(ta, .{
                    .ts_unix_ms = now_ms,
                    .request_id = request_id,
                    .prompt_hash = b.prompt_hash_hex,
                    .decision = "delegation.token.turns_exhausted",
                    .subject = active_agent.id,
                    .allowed = false,
                    .reason = "denied: delegation token max_turns exhausted",
                    .policy_hash = run_cfg.policy.policyHash(),
                }, ledger_ptr);
                logger.logJson(ta, .agent_run, request_id, .{
                    .status = "delegation_token_turns_exhausted",
                    .turn = turn,
                    .agent_id = active_agent.id,
                    .token_hash = parent_token.token_hash[0..],
                });
                return error.DelegateTokenTurnsExceeded;
            }
        }

        if (try cancelRequested(opts)) {
            logger.logJson(ta, .agent_run, request_id, .{
                .status = "canceled",
                .turn = turn,
                .agent_id = active_agent.id,
            });
            return error.Canceled;
        }

        logger.logJson(ta, .provider_call, request_id, .{
            .kind = @tagName(run_cfg.raw.provider_primary.kind),
            .model = run_cfg.raw.provider_primary.model,
            .status = "start",
            .turn = turn,
            .agent_id = active_agent.id,
        });
        recorder.record(.provider_request, turn, .{
            .kind = @tagName(run_cfg.raw.provider_primary.kind),
            .model = run_cfg.raw.provider_primary.model,
            .tools = tool_defs.len,
            .messages = messages.items.len,
        }) catch {};

        const resp = provider.chat(ta, io, .{
            .messages = messages.items,
            .tools = tool_defs,
            .model = run_cfg.raw.provider_primary.model,
            .temperature = run_cfg.raw.provider_primary.temperature,
            .meta = .{ .request_id = request_id, .prompt_hash = b.prompt_hash_hex },
        }) catch |e| {
            logger.logJson(ta, .provider_call, request_id, .{
                .kind = @tagName(run_cfg.raw.provider_primary.kind),
                .model = run_cfg.raw.provider_primary.model,
                .status = "error",
                .error_name = @errorName(e),
                .turn = turn,
                .agent_id = active_agent.id,
            });
            return e;
        };

        logger.logJson(ta, .provider_call, request_id, .{
            .kind = @tagName(run_cfg.raw.provider_primary.kind),
            .model = run_cfg.raw.provider_primary.model,
            .status = "ok",
            .bytes_out = resp.content.len,
            .tool_calls_count = resp.tool_calls.len,
            .finish_reason = @tagName(resp.finish_reason),
            .turn = turn,
            .prompt_tokens = resp.usage.prompt_tokens,
            .completion_tokens = resp.usage.completion_tokens,
            .total_tokens = resp.usage.total_tokens,
            .agent_id = active_agent.id,
        });
        recorder.record(.provider_response, turn, .{
            .finish_reason = @tagName(resp.finish_reason),
            .content = resp.content,
            .tool_calls = resp.tool_calls.len,
            .usage = .{
                .prompt_tokens = resp.usage.prompt_tokens,
                .completion_tokens = resp.usage.completion_tokens,
                .total_tokens = resp.usage.total_tokens,
            },
        }) catch {};

        if (opts.verbose) {
            verboseLog(io, "[verbose] turn={d} finish_reason={s} content_bytes={d} tool_calls={d} tokens={d}/{d}/{d}\n", .{
                turn,                     @tagName(resp.finish_reason), resp.content.len,        resp.tool_calls.len,
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
            recorder.record(.run_end, turn, .{
                .content = resp.content,
                .turns = turn + 1,
            }) catch {};
            const attestation = try finalizeAttestation(
                a,
                io,
                run_cfg,
                request_id,
                b.prompt_hash_hex,
                ts_start_ms,
                decision_log.nowUnixMs(io),
                ledger_enabled,
                &ledger,
                tool_args_hashes.items,
                tool_output_hashes.items,
            );
            recorder.finalize(run_cfg, run_cfg.policy.policyHash(), b.prompt_hash_hex) catch {};
            return .{
                .content = try a.dupe(u8, resp.content),
                .turns = turn + 1,
                .attestation = attestation,
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
            const args_hash = try hash_mod.sha256HexAlloc(a, tc.arguments);
            try tool_args_hashes.append(args_hash);
            recorder.record(.tool_request, turn, .{
                .tool = tc.name,
                .tool_call_id = tc.id,
                .arguments = tc.arguments,
            }) catch {};

            if (try cancelRequested(opts)) {
                logger.logJson(ta, .agent_run, request_id, .{
                    .status = "canceled",
                    .turn = turn,
                    .agent_id = active_agent.id,
                });
                return error.Canceled;
            }

            logger.logJson(ta, .tool_run, request_id, .{
                .tool = tc.name,
                .tool_call_id = tc.id,
                .turn = turn,
                .status = "start",
                .agent_id = active_agent.id,
            });

            if (try provider.replayToolResult(ta, tc.id)) |replayed| {
                const out_hash = try hash_mod.sha256HexAlloc(a, replayed.content);
                try tool_output_hashes.append(out_hash);
                recorder.record(.tool_response, turn, .{
                    .tool = tc.name,
                    .tool_call_id = tc.id,
                    .ok = replayed.ok,
                    .content = replayed.content,
                }) catch {};

                logger.logJson(ta, .tool_run, request_id, .{
                    .tool = tc.name,
                    .tool_call_id = tc.id,
                    .turn = turn,
                    .status = "replayed",
                    .ok = replayed.ok,
                    .agent_id = active_agent.id,
                });

                try messages.append(.{
                    .role = .tool,
                    .content = replayed.content,
                    .tool_call_id = tc.id,
                });
                continue;
            }

            if (std.mem.eql(u8, tc.name, delegate_tool_name)) {
                const delegate_args = parseDelegateArgs(ta, tc.arguments) catch null;
                if (delegate_args) |da| {
                    recorder.record(.delegation_start, turn, .{
                        .target_agent = da.target_agent,
                    }) catch {};
                }
                const delegate_json = handleDelegateToolCall(ta, io, run_cfg, request_id, b.prompt_hash_hex, active_agent, tc.arguments, opts, ledger_ptr) catch |e| {
                    const err_msg = try std.fmt.allocPrint(ta, "Tool execution error: {s}", .{@errorName(e)});
                    const out_hash = try hash_mod.sha256HexAlloc(a, err_msg);
                    try tool_output_hashes.append(out_hash);
                    recorder.record(.tool_response, turn, .{
                        .tool = tc.name,
                        .tool_call_id = tc.id,
                        .ok = false,
                        .@"error" = @errorName(e),
                    }) catch {};
                    logger.logJson(ta, .tool_run, request_id, .{
                        .tool = tc.name,
                        .tool_call_id = tc.id,
                        .turn = turn,
                        .status = "error",
                        .error_name = @errorName(e),
                        .agent_id = active_agent.id,
                    });
                    try messages.append(.{
                        .role = .tool,
                        .content = err_msg,
                        .tool_call_id = tc.id,
                    });
                    continue;
                };
                const out_hash = try hash_mod.sha256HexAlloc(a, delegate_json);
                try tool_output_hashes.append(out_hash);
                if (delegate_args) |da| {
                    recorder.record(.delegation_end, turn, .{
                        .target_agent = da.target_agent,
                        .ok = true,
                    }) catch {};
                }
                recorder.record(.tool_response, turn, .{
                    .tool = tc.name,
                    .tool_call_id = tc.id,
                    .ok = true,
                    .content = delegate_json,
                }) catch {};

                logger.logJson(ta, .tool_run, request_id, .{
                    .tool = tc.name,
                    .tool_call_id = tc.id,
                    .turn = turn,
                    .status = "ok",
                    .ok = true,
                    .agent_id = active_agent.id,
                });

                try messages.append(.{
                    .role = .tool,
                    .content = delegate_json,
                    .tool_call_id = tc.id,
                });
                continue;
            }

            const tool_result = tools_runner.run(ta, io, run_cfg, request_id, tc.name, tc.arguments, .{
                .prompt_hash = b.prompt_hash_hex,
                .ledger = ledger_ptr,
                .cache = &cache,
            }) catch |e| {
                // Tool execution failed - send error back to LLM
                const err_msg = try std.fmt.allocPrint(ta, "Tool execution error: {s}", .{@errorName(e)});
                const out_hash = try hash_mod.sha256HexAlloc(a, err_msg);
                try tool_output_hashes.append(out_hash);
                recorder.record(.tool_response, turn, .{
                    .tool = tc.name,
                    .tool_call_id = tc.id,
                    .ok = false,
                    .@"error" = @errorName(e),
                }) catch {};

                logger.logJson(ta, .tool_run, request_id, .{
                    .tool = tc.name,
                    .tool_call_id = tc.id,
                    .turn = turn,
                    .status = "error",
                    .error_name = @errorName(e),
                    .agent_id = active_agent.id,
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
                .agent_id = active_agent.id,
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
            const out_hash = try hash_mod.sha256HexAlloc(a, result_content);
            try tool_output_hashes.append(out_hash);
            recorder.record(.tool_response, turn, .{
                .tool = tc.name,
                .tool_call_id = tc.id,
                .ok = tool_result.ok,
                .content = result_content,
            }) catch {};

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
        .agent_id = active_agent.id,
    });
    recorder.record(.run_end, max_agent_turns, .{
        .content = "Agent reached maximum number of turns without completing.",
        .turns = max_agent_turns,
    }) catch {};

    const attestation = try finalizeAttestation(
        a,
        io,
        run_cfg,
        request_id,
        b.prompt_hash_hex,
        ts_start_ms,
        decision_log.nowUnixMs(io),
        ledger_enabled,
        &ledger,
        tool_args_hashes.items,
        tool_output_hashes.items,
    );
    recorder.finalize(run_cfg, run_cfg.policy.policyHash(), b.prompt_hash_hex) catch {};
    return .{
        .content = try a.dupe(u8, "Agent reached maximum number of turns without completing."),
        .turns = max_agent_turns,
        .attestation = attestation,
    };
}

/// Load tool definitions for all tools allowed by the active policy preset.
/// Returns a slice of ToolDef suitable for passing to the provider.
fn loadToolDefs(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    delegate_targets: []const []const u8,
) ![]const provider_mod.ToolDef {
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

    if (delegate_targets.len > 0) {
        const schema_json = try buildDelegateSchemaJsonAlloc(a, delegate_targets);
        const names_txt = try joinNamesAlloc(a, delegate_targets);
        defer a.free(names_txt);
        const desc = try std.fmt.allocPrint(
            a,
            "Delegate work to another configured agent. Allowed targets: {s}",
            .{names_txt},
        );
        try defs.append(.{
            .name = try a.dupe(u8, delegate_tool_name),
            .description = desc,
            .parameters_json = schema_json,
        });
    }

    return try defs.toOwnedSlice();
}

fn buildDelegateSchemaJsonAlloc(a: std.mem.Allocator, delegate_targets: []const []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("object");

    try stream.objectField("required");
    try stream.beginArray();
    try stream.write("target_agent");
    try stream.write("message");
    try stream.endArray();

    try stream.objectField("properties");
    try stream.beginObject();

    try stream.objectField("target_agent");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("string");
    try stream.objectField("enum");
    try stream.beginArray();
    for (delegate_targets) |t| try stream.write(t);
    try stream.endArray();
    try stream.endObject();

    try stream.objectField("message");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("string");
    try stream.objectField("max_length");
    try stream.write(@as(u32, 8192));
    try stream.endObject();

    try stream.objectField("requested_scope");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("object");
    try stream.objectField("properties");
    try stream.beginObject();

    try stream.objectField("allowed_tools");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("array");
    try stream.objectField("items");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("string");
    try stream.endObject();
    try stream.endObject();

    try stream.objectField("write_paths");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("array");
    try stream.objectField("items");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("string");
    try stream.endObject();
    try stream.endObject();

    try stream.objectField("allow_network");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("boolean");
    try stream.endObject();

    try stream.objectField("max_turns");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("integer");
    try stream.endObject();

    try stream.objectField("expiry_ms");
    try stream.beginObject();
    try stream.objectField("type");
    try stream.write("integer");
    try stream.endObject();

    try stream.endObject(); // requested_scope.properties
    try stream.endObject(); // requested_scope

    try stream.endObject(); // properties
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn joinNamesAlloc(a: std.mem.Allocator, names: []const []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    for (names, 0..) |n, i| {
        if (i > 0) try aw.writer.writeAll(", ");
        try aw.writer.print("@{s}", .{n});
    }
    return try aw.toOwnedSlice();
}

const DelegateArgs = struct {
    target_agent: []const u8,
    message: []const u8,
    requested_scope: token_mod.RequestedScope = .{},
};

fn parseDelegateArgs(a: std.mem.Allocator, args_json: []const u8) !DelegateArgs {
    var parsed = try std.json.parseFromSlice(std.json.Value, a, args_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidDelegateArgs;

    const obj = parsed.value.object;
    const target_v = obj.get("target_agent") orelse return error.InvalidDelegateArgs;
    const message_v = obj.get("message") orelse return error.InvalidDelegateArgs;
    if (target_v != .string or message_v != .string) return error.InvalidDelegateArgs;
    if (message_v.string.len == 0) return error.InvalidDelegateArgs;

    var scope: token_mod.RequestedScope = .{};
    if (obj.get("requested_scope")) |scope_v| {
        if (scope_v != .object) return error.InvalidDelegateArgs;
        const scope_obj = scope_v.object;
        scope.allowed_tools = try parseOptionalStringArrayDup(a, scope_obj, "allowed_tools");
        scope.write_paths = try parseOptionalStringArrayDup(a, scope_obj, "write_paths");
        scope.allow_network = try parseOptionalBool(scope_obj, "allow_network");
        scope.max_turns = try parseOptionalUsize(scope_obj, "max_turns");
        scope.expiry_ms = try parseOptionalI64(scope_obj, "expiry_ms");
    }

    return .{
        .target_agent = target_v.string,
        .message = message_v.string,
        .requested_scope = scope,
    };
}

fn parseOptionalStringArrayDup(
    a: std.mem.Allocator,
    obj: std.json.ObjectMap,
    key: []const u8,
) !?[]const []const u8 {
    const value = obj.get(key) orelse return null;
    if (value != .array) return error.InvalidDelegateArgs;

    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |item| a.free(item);
        out.deinit();
    }
    for (value.array.items) |entry| {
        if (entry != .string) return error.InvalidDelegateArgs;
        if (entry.string.len == 0) return error.InvalidDelegateArgs;
        try out.append(try a.dupe(u8, entry.string));
    }
    return try out.toOwnedSlice();
}

fn parseOptionalBool(obj: std.json.ObjectMap, key: []const u8) !?bool {
    const value = obj.get(key) orelse return null;
    if (value != .bool) return error.InvalidDelegateArgs;
    return value.bool;
}

fn parseOptionalUsize(obj: std.json.ObjectMap, key: []const u8) !?usize {
    const value = obj.get(key) orelse return null;
    if (value != .integer) return error.InvalidDelegateArgs;
    if (value.integer <= 0) return error.InvalidDelegateArgs;
    if (value.integer > std.math.maxInt(usize)) return error.InvalidDelegateArgs;
    return @as(usize, @intCast(value.integer));
}

fn parseOptionalI64(obj: std.json.ObjectMap, key: []const u8) !?i64 {
    const value = obj.get(key) orelse return null;
    if (value != .integer) return error.InvalidDelegateArgs;
    return value.integer;
}

fn isAllowedDelegate(source: config.AgentProfileConfig, target: []const u8) bool {
    for (source.delegate_to) |id| {
        if (std.mem.eql(u8, id, target)) return true;
    }
    return false;
}

fn handleDelegateToolCall(
    a: std.mem.Allocator,
    io: std.Io,
    parent_cfg: config.ValidatedConfig,
    request_id: []const u8,
    prompt_hash: []const u8,
    active_agent: ActiveAgent,
    args_json: []const u8,
    opts: RunOptions,
    ledger: ?*att_ledger.MerkleTree,
) ![]u8 {
    const profile = active_agent.profile orelse return error.DelegateNotAllowed;
    if (profile.delegate_to.len == 0) return error.DelegateNotAllowed;
    if (opts.delegate_depth >= opts.max_delegate_depth) return error.DelegateDepthExceeded;

    const args = try parseDelegateArgs(a, args_json);
    if (!isAllowedDelegate(profile, args.target_agent)) return error.DelegateTargetDenied;
    _ = findAgentProfile(parent_cfg.raw, args.target_agent) orelse return error.UnknownAgent;

    var token = try token_mod.mint(a, .{
        .allowed_tools = parent_cfg.policy.active.tools,
        .write_paths = parent_cfg.policy.active.allow_write_paths,
        .allow_network = parent_cfg.policy.active.allow_network,
    }, args.requested_scope);
    defer token.deinit(a);

    const decisions = decision_log.Logger.fromConfig(parent_cfg, io);
    const token_reason = try std.fmt.allocPrint(a, "minted token hash={s} tools={d}->{d} write_paths={d}->{d} network={s}->{s}", .{
        token.token_hash[0..],
        parent_cfg.policy.active.tools.len,
        token.allowed_tools.len,
        parent_cfg.policy.active.allow_write_paths.len,
        token.write_paths.len,
        if (parent_cfg.policy.active.allow_network) "true" else "false",
        if (token.allow_network) "true" else "false",
    });
    defer a.free(token_reason);
    decisions.logAndRecord(a, .{
        .ts_unix_ms = decision_log.nowUnixMs(io),
        .request_id = request_id,
        .prompt_hash = prompt_hash,
        .decision = "delegation.token.mint",
        .subject = args.target_agent,
        .allowed = true,
        .reason = token_reason,
        .policy_hash = parent_cfg.policy.policyHash(),
    }, ledger);

    var child_opts = opts;
    child_opts.interactive = false;
    child_opts.agent_id = args.target_agent;
    child_opts.delegate_depth += 1;
    child_opts.parent_token = &token;

    var child_res = try runLoop(a, io, parent_cfg, args.message, request_id, child_opts);
    defer child_res.deinit(a);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("delegated_by");
    try stream.write(active_agent.id);
    try stream.objectField("delegated_to");
    try stream.write(args.target_agent);
    try stream.objectField("turns");
    try stream.write(child_res.turns);
    try stream.objectField("content");
    try stream.write(child_res.content);
    try stream.objectField("token_hash");
    try stream.write(token.token_hash[0..]);
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn resolveActiveAgent(a: std.mem.Allocator, cfg: config.ValidatedConfig, requested: ?[]const u8) !ActiveAgent {
    if (cfg.raw.orchestration.agents.len == 0) {
        if (requested != null) return error.UnknownAgent;
        return .{ .id = "default", .profile = null };
    }

    const id = requested orelse blk: {
        if (cfg.raw.orchestration.leader_agent.len > 0) break :blk cfg.raw.orchestration.leader_agent;
        break :blk cfg.raw.orchestration.agents[0].id;
    };

    const prof = findAgentProfile(cfg.raw, id) orelse return error.UnknownAgent;
    _ = a;
    return .{ .id = prof.id, .profile = prof };
}

fn findAgentProfile(raw: config.Config, id: []const u8) ?config.AgentProfileConfig {
    for (raw.orchestration.agents) |ag| {
        if (std.mem.eql(u8, ag.id, id)) return ag;
    }
    return null;
}

fn cfgForAgent(
    a: std.mem.Allocator,
    cfg: config.ValidatedConfig,
    active: ActiveAgent,
    parent_token: ?*const token_mod.CapabilityToken,
) !config.ValidatedConfig {
    var out = cfg;
    if (active.profile) |p| {
        if (!std.mem.eql(u8, p.capability_preset, cfg.raw.capabilities.active_preset)) {
            var caps = cfg.raw.capabilities;
            caps.active_preset = p.capability_preset;
            out.policy = try policy_mod.Policy.fromConfig(a, caps, cfg.raw.security.workspace_root);
        }
    }
    if (parent_token) |token| {
        out.policy = try policy_mod.Policy.attenuate(a, out.policy, token.*);
    }
    return out;
}

fn finalizeAttestation(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    request_id: []const u8,
    prompt_hash: ?[]const u8,
    ts_start_ms: i64,
    ts_end_ms: i64,
    enabled: bool,
    ledger: *const att_ledger.MerkleTree,
    tool_args_hashes: []const []const u8,
    tool_output_hashes: []const []const u8,
) !?Attestation {
    if (!enabled) return null;

    var receipt = try att_receipt.buildFromLedger(
        a,
        request_id,
        cfg.policy.policyHash(),
        prompt_hash,
        ts_start_ms,
        ts_end_ms,
        ledger,
        tool_args_hashes,
        tool_output_hashes,
    );
    defer receipt.deinit(a);

    const path = try att_receipt.writeReceiptFile(a, io, cfg.raw.security.workspace_root, receipt);
    defer a.free(path);

    return .{
        .merkle_root_hex = receipt.merkle_root_hex,
        .event_count = receipt.event_count,
    };
}

/// Write a formatted line to stderr (best-effort, for --verbose output).
fn verboseLog(io: std.Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    w.interface.print(fmt, args) catch {};
    w.flush() catch {};
}

fn cancelRequested(opts: RunOptions) anyerror!bool {
    const chk = opts.cancel_check orelse return false;
    return chk.func(chk.ctx);
}
