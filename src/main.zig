const std = @import("std");
const App = @import("app.zig").App;
const config_mod = @import("config.zig");
const doctor = @import("doctor.zig");

pub fn main(init: std.process.Init) !void {
    const argv = init.minimal.args.toSlice(init.arena.allocator()) catch |e| {
        try printCliError(init.io, &.{}, e);
        std.process.exit(1);
    };

    run(init, argv) catch |e| {
        try printCliError(init.io, argv, e);
        std.process.exit(1);
    };
}

fn run(init: std.process.Init, argv: []const [:0]const u8) !void {
    const a = init.gpa;
    const io = init.io;

    if (argv.len < 2) {
        try usage(io);
        return;
    }

    const cmd: []const u8 = argv[1];
    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        try usage(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "--help-all")) {
        try usageAll(io);
        return;
    }

    if (argv.len >= 3 and isHelpArg(argv[2])) {
        if (std.mem.eql(u8, cmd, "agent")) return usageAgent(io);
        if (std.mem.eql(u8, cmd, "chat")) return usageChat(io);
        if (std.mem.eql(u8, cmd, "doctor")) return usageDoctor(io);
        if (std.mem.eql(u8, cmd, "update")) return usageUpdate(io);
        if (std.mem.eql(u8, cmd, "run")) return usageRun(io);
        if (std.mem.eql(u8, cmd, "ops")) return usageOps(io);
        if (std.mem.eql(u8, cmd, "vault")) return usageVault(io);
        if (std.mem.eql(u8, cmd, "config")) return usageConfig(io);
        if (std.mem.eql(u8, cmd, "prompt")) return usagePrompt(io);
        if (std.mem.eql(u8, cmd, "tools")) return usageTools(io);
        if (std.mem.eql(u8, cmd, "task")) return usageTask(io);
        if (std.mem.eql(u8, cmd, "templates")) return usageTemplates(io);
        if (std.mem.eql(u8, cmd, "queue")) return usageQueue(io);
        if (std.mem.eql(u8, cmd, "git")) return usageGit(io);
        if (std.mem.eql(u8, cmd, "policy")) return usagePolicy(io);
        if (std.mem.eql(u8, cmd, "audit")) return usageAudit(io);
        if (std.mem.eql(u8, cmd, "attest")) return usageAttest(io);
        if (std.mem.eql(u8, cmd, "replay")) return usageReplay(io);
        if (std.mem.eql(u8, cmd, "gateway")) return usageGateway(io);
        if (std.mem.eql(u8, cmd, "completion")) return usageCompletion(io);
        if (std.mem.eql(u8, cmd, "init")) return usageInit(io);
        if (std.mem.eql(u8, cmd, "setup")) return usageSetup(io);
    }

    if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version")) {
        const build_options = @import("build_options");
        const builtin = @import("builtin");
        const as_json = hasFlag(argv, "--json");
        var obuf: [256]u8 = undefined;
        var ow = std.Io.File.stdout().writer(io, &obuf);
        if (as_json) {
            const out = try jsonObj(a, .{
                .version = build_options.version,
                .arch = @tagName(builtin.cpu.arch),
                .os = @tagName(builtin.os.tag),
            });
            defer a.free(out);
            try ow.interface.print("{s}\n", .{out});
        } else {
            try ow.interface.print("zigclaw {s} ({s}-{s})\n", .{
                build_options.version,
                @tagName(builtin.cpu.arch),
                @tagName(builtin.os.tag),
            });
        }
        try ow.flush();
        return;
    }

    if (std.mem.eql(u8, cmd, "setup")) {
        try runOnboarding(a, io, true, false);
        return;
    }

    if (std.mem.eql(u8, cmd, "chat")) {
        const term = @import("util/term.zig");
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        const verbose = hasFlag(argv, "--verbose");
        const agent_id = flagValue(argv, "--agent");
        const as_json = hasFlag(argv, "--json");
        const model_override = flagValue(argv, "--model");
        const preset_override = flagValue(argv, "--preset");

        var app_c = try App.init(a, io);
        defer app_c.deinit();
        var validated = try app_c.loadConfig(cfg_path);
        defer validated.deinit(a);

        // Zero-config: auto-switch stub to openai_compat when API key is present
        applyEnvDefaults(&validated);

        // Env var overrides (lower priority than CLI flags)
        applyEnvOverrides(&validated);

        // CLI flags take highest priority
        if (model_override) |m| validated.raw.provider_primary.model = m;
        if (preset_override) |p| validated.raw.capabilities.active_preset = p;

        // Positional message: zigclaw chat "something"
        const positional_msg: ?[]const u8 = if (argv.len >= 3 and argv[2][0] != '-') argv[2] else null;
        const explicit_msg = flagValue(argv, "--message");
        const piped_msg: ?[]const u8 = if (positional_msg == null and explicit_msg == null and !term.stdinIsTty()) blk: {
            const stdin = std.Io.File.stdin();
            var rbuf: [4096]u8 = undefined;
            var reader = stdin.reader(io, &rbuf);
            break :blk reader.interface.allocRemaining(a, std.Io.Limit.limited(1 * 1024 * 1024)) catch null;
        } else null;
        defer if (piped_msg) |pm| a.free(pm);

        const msg = positional_msg orelse explicit_msg orelse piped_msg orelse null;
        const interactive = msg == null;

        if (as_json and interactive) return error.InvalidArgs;

        if (as_json) {
            const trace = @import("obs/trace.zig");
            const loop = @import("agent/loop.zig");
            const rid = trace.newRequestId(io);
            var result = try loop.runLoop(a, io, validated, msg.?, rid.slice(), .{
                .verbose = verbose,
                .interactive = false,
                .agent_id = agent_id,
            });
            defer result.deinit(a);
            const out = try jsonObj(a, .{
                .request_id = rid.slice(),
                .turns = result.turns,
                .content = result.content,
            });
            defer a.free(out);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
        } else if (interactive) {
            try app_c.runAgent(validated, "hello", .{
                .verbose = verbose,
                .interactive = true,
                .agent_id = agent_id,
            });
        } else {
            // Non-interactive, non-json: print thinking... then result
            {
                var ebuf: [256]u8 = undefined;
                var ew = std.Io.File.stderr().writer(io, &ebuf);
                try ew.interface.writeAll("thinking...\n");
                try ew.flush();
            }
            const trace = @import("obs/trace.zig");
            const loop = @import("agent/loop.zig");
            const rid = trace.newRequestId(io);
            var result = try loop.runLoop(a, io, validated, msg.?, rid.slice(), .{
                .verbose = verbose,
                .interactive = false,
                .agent_id = agent_id,
            });
            defer result.deinit(a);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{result.content});
            try ow.flush();
        }
        return;
    }

    if (std.mem.eql(u8, cmd, "completion")) {
        if (argv.len < 3) return error.InvalidArgs;
        const shell = argv[2];
        const script = completionScript(shell) orelse return error.InvalidArgs;
        var obuf: [8192]u8 = undefined;
        var ow = std.Io.File.stdout().writer(io, &obuf);
        try ow.interface.writeAll(script);
        if (script.len == 0 or script[script.len - 1] != '\n') try ow.interface.writeAll("\n");
        try ow.flush();
        return;
    }

    if (std.mem.eql(u8, cmd, "doctor")) {
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        const as_json = hasFlag(argv, "--json");
        try doctor.run(a, io, cfg_path, as_json);
        return;
    }

    if (std.mem.eql(u8, cmd, "update")) {
        const as_json = hasFlag(argv, "--json");
        const check_only = hasFlag(argv, "--check");
        const manifest_url = flagValue(argv, "--url") orelse "https://github.com/zigclaw/zigclaw/releases/latest/download/latest.json";
        const updater = @import("update/updater.zig");
        const build_options = @import("build_options");

        if (check_only) {
            const result = try updater.check(a, io, manifest_url);
            defer a.free(result.latest);
            if (result.download_url) |u| a.free(u);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (as_json) {
                const out = try jsonObj(a, .{
                    .ok = true,
                    .check_only = true,
                    .current = result.current,
                    .latest = result.latest,
                    .update_available = result.update_available,
                    .download_url = result.download_url,
                    .manifest_url = manifest_url,
                });
                defer a.free(out);
                try ow.interface.print("{s}\n", .{out});
            } else {
                if (result.update_available) {
                    try ow.interface.print("update available: {s} -> {s}\n", .{ result.current, result.latest });
                } else {
                    try ow.interface.print("up to date: {s}\n", .{result.current});
                }
            }
            try ow.flush();
        } else {
            const new_version = updater.update(a, io, manifest_url) catch |e| {
                if (e == error.AlreadyUpToDate) {
                    var obuf: [4096]u8 = undefined;
                    var ow = std.Io.File.stdout().writer(io, &obuf);
                    if (as_json) {
                        const out = try jsonObj(a, .{
                            .ok = true,
                            .updated = false,
                            .current = build_options.version,
                            .latest = build_options.version,
                            .manifest_url = manifest_url,
                        });
                        defer a.free(out);
                        try ow.interface.print("{s}\n", .{out});
                    } else {
                        try ow.interface.print("already up to date: {s}\n", .{build_options.version});
                    }
                    try ow.flush();
                    return;
                }
                return e;
            };
            defer a.free(new_version);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (as_json) {
                const out = try jsonObj(a, .{
                    .ok = true,
                    .updated = true,
                    .current = build_options.version,
                    .latest = new_version,
                    .manifest_url = manifest_url,
                });
                defer a.free(out);
                try ow.interface.print("{s}\n", .{out});
            } else {
                try ow.interface.print("updated to {s}\n", .{new_version});
            }
            try ow.flush();
        }
        return;
    }

    if (std.mem.eql(u8, cmd, "vault")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const as_json = hasFlag(argv, "--json");
        const vault_path = flagValue(argv, "--vault") orelse "./.zigclaw/vault.enc";
        const vault_mod = @import("vault/vault.zig");
        const prompts_mod = @import("setup/prompts.zig");

        if (std.mem.eql(u8, sub, "set")) {
            if (argv.len < 4) return error.InvalidArgs;
            const name: []const u8 = argv[3];

            var val_buf: [4096]u8 = undefined;
            const value = try prompts_mod.readSecretLine(io, "Secret value (hidden): ", &val_buf);
            if (value.len == 0) return error.InvalidArgs;

            var pass_buf: [256]u8 = undefined;
            const passphrase = try prompts_mod.readSecretLine(io, "Vault passphrase (hidden): ", &pass_buf);
            if (passphrase.len == 0) return error.InvalidArgs;

            var v = try vault_mod.open(a, io, vault_path, passphrase);
            defer v.deinit();
            try v.set(name, value);
            try vault_mod.save(&v, a, io, vault_path, passphrase);

            var obuf: [256]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (as_json) {
                const out = try jsonObj(a, .{
                    .ok = true,
                    .action = "set",
                    .name = name,
                    .vault_path = vault_path,
                });
                defer a.free(out);
                try ow.interface.print("{s}\n", .{out});
            } else {
                try ow.interface.print("stored '{s}' in vault\n", .{name});
            }
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "get")) {
            if (argv.len < 4) return error.InvalidArgs;
            const name: []const u8 = argv[3];

            var pass_buf: [256]u8 = undefined;
            const passphrase = try prompts_mod.readSecretLine(io, "Vault passphrase (hidden): ", &pass_buf);
            if (passphrase.len == 0) return error.InvalidArgs;

            var v = try vault_mod.open(a, io, vault_path, passphrase);
            defer v.deinit();

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (v.get(name)) |val| {
                if (as_json) {
                    const out = try jsonObj(a, .{
                        .ok = true,
                        .name = name,
                        .found = true,
                        .value = val,
                    });
                    defer a.free(out);
                    try ow.interface.print("{s}\n", .{out});
                } else {
                    try ow.interface.print("{s}\n", .{val});
                }
            } else {
                if (as_json) {
                    const out = try jsonObj(a, .{
                        .ok = true,
                        .name = name,
                        .found = false,
                        .value = @as(?[]const u8, null),
                    });
                    defer a.free(out);
                    try ow.interface.print("{s}\n", .{out});
                } else {
                    try ow.interface.print("key '{s}' not found\n", .{name});
                }
            }
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "list")) {
            var pass_buf: [256]u8 = undefined;
            const passphrase = try prompts_mod.readSecretLine(io, "Vault passphrase (hidden): ", &pass_buf);
            if (passphrase.len == 0) return error.InvalidArgs;

            var v = try vault_mod.open(a, io, vault_path, passphrase);
            defer v.deinit();

            const names = try v.list(a);
            defer {
                for (names) |n| a.free(n);
                a.free(names);
            }

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (as_json) {
                const out = try jsonObj(a, .{
                    .ok = true,
                    .count = names.len,
                    .names = names,
                });
                defer a.free(out);
                try ow.interface.print("{s}\n", .{out});
            } else {
                if (names.len == 0) {
                    try ow.interface.writeAll("(vault is empty)\n");
                } else {
                    for (names) |n| {
                        try ow.interface.print("{s}\n", .{n});
                    }
                }
            }
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "delete")) {
            if (argv.len < 4) return error.InvalidArgs;
            const name: []const u8 = argv[3];

            var pass_buf: [256]u8 = undefined;
            const passphrase = try prompts_mod.readSecretLine(io, "Vault passphrase (hidden): ", &pass_buf);
            if (passphrase.len == 0) return error.InvalidArgs;

            var v = try vault_mod.open(a, io, vault_path, passphrase);
            defer v.deinit();

            var obuf: [256]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (v.delete(name)) {
                try vault_mod.save(&v, a, io, vault_path, passphrase);
                if (as_json) {
                    const out = try jsonObj(a, .{
                        .ok = true,
                        .action = "delete",
                        .name = name,
                        .deleted = true,
                    });
                    defer a.free(out);
                    try ow.interface.print("{s}\n", .{out});
                } else {
                    try ow.interface.print("deleted '{s}'\n", .{name});
                }
            } else {
                if (as_json) {
                    const out = try jsonObj(a, .{
                        .ok = true,
                        .action = "delete",
                        .name = name,
                        .deleted = false,
                    });
                    defer a.free(out);
                    try ow.interface.print("{s}\n", .{out});
                } else {
                    try ow.interface.print("key '{s}' not found\n", .{name});
                }
            }
            try ow.flush();
            return;
        }

        try usageVault(io);
        return;
    }

    var app = try App.init(a, io);
    defer app.deinit();

    if (std.mem.eql(u8, cmd, "run")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        if (std.mem.eql(u8, sub, "summary")) {
            const rid = flagValue(argv, "--request-id") orelse return error.InvalidArgs;
            const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
            const as_json = hasFlag(argv, "--json");

            var validated = try app.loadConfig(cfg_path);
            defer validated.deinit(a);

            try printRunSummary(a, io, validated, rid, as_json);
            return;
        }
        try usageRun(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "ops")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "summary";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        const format = flagValue(argv, "--format") orelse "text";
        const limit: usize = if (flagValue(argv, "--limit")) |s| try std.fmt.parseInt(usize, s, 10) else 5;
        const poll_ms: u32 = if (flagValue(argv, "--poll-ms")) |s| try std.fmt.parseInt(u32, s, 10) else 1500;
        const iterations: ?usize = if (flagValue(argv, "--iterations")) |s| try std.fmt.parseInt(usize, s, 10) else null;

        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (std.mem.eql(u8, sub, "summary")) {
            const as_json = std.mem.eql(u8, format, "json");
            try printOpsSnapshot(a, io, validated, limit, as_json);
            return;
        }

        if (std.mem.eql(u8, sub, "watch")) {
            const as_json = std.mem.eql(u8, format, "json");
            var i: usize = 0;
            while (true) : (i += 1) {
                if (!as_json) {
                    var clear_buf: [64]u8 = undefined;
                    var clear_w = std.Io.File.stdout().writer(io, &clear_buf);
                    try clear_w.interface.writeAll("\x1b[2J\x1b[H");
                    try clear_w.flush();
                }
                try printOpsSnapshot(a, io, validated, limit, as_json);
                if (iterations) |n| if (i + 1 >= n) break;
                io.sleep(std.Io.Duration.fromMilliseconds(@intCast(poll_ms)), .awake) catch {};
            }
            return;
        }

        try usageOps(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "audit")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        const report_mod = @import("audit/report.zig");

        if (std.mem.eql(u8, sub, "report")) {
            const rid = flagValue(argv, "--request-id");
            const from_ts = if (flagValue(argv, "--from")) |s| try std.fmt.parseInt(i64, s, 10) else null;
            const to_ts = if (flagValue(argv, "--to")) |s| try std.fmt.parseInt(i64, s, 10) else null;
            const format = flagValue(argv, "--format") orelse "text";

            var report = try report_mod.buildReport(
                a,
                io,
                validated.raw.logging.dir,
                validated.raw.logging.file,
                validated.raw.security.workspace_root,
                rid,
                from_ts,
                to_ts,
            );
            defer report.deinit(a);

            const out = if (std.mem.eql(u8, format, "json"))
                try report_mod.formatJson(a, report)
            else
                try report_mod.formatText(a, report);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "verify")) {
            const rid = flagValue(argv, "--request-id") orelse return error.InvalidArgs;
            const format = flagValue(argv, "--format") orelse "json";

            const receipt_json = try @import("attestation/receipt.zig").readReceiptJsonAlloc(
                a,
                io,
                validated.raw.security.workspace_root,
                rid,
            );
            defer a.free(receipt_json);

            const verify_mod = @import("audit/verify.zig");
            var result = try verify_mod.verifyAllEvents(a, receipt_json);
            defer result.deinit(a);

            const out = if (std.mem.eql(u8, format, "text")) blk: {
                // Wrap in a minimal report for text formatting
                var report = report_mod.AuditReport{
                    .request_id = rid,
                    .events = &.{},
                    .verify_result = result,
                    .from_ts = null,
                    .to_ts = null,
                };
                // Don't deinit: result and events are borrowed
                _ = &report;
                break :blk try report_mod.formatText(a, report);
            } else try verify_mod.verifyResultJsonAlloc(a, result);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "summary")) {
            const from_ts = if (flagValue(argv, "--from")) |s| try std.fmt.parseInt(i64, s, 10) else null;
            const to_ts = if (flagValue(argv, "--to")) |s| try std.fmt.parseInt(i64, s, 10) else null;
            const format = flagValue(argv, "--format") orelse "text";

            const log_reader = @import("audit/log_reader.zig");
            const events = try log_reader.readEvents(a, io, validated.raw.logging.dir, validated.raw.logging.file, .{
                .from_ts = from_ts,
                .to_ts = to_ts,
            });
            defer log_reader.freeEvents(a, events);

            var stats = try report_mod.buildSummary(a, events);
            defer stats.deinit(a);

            const out = if (std.mem.eql(u8, format, "json"))
                try report_mod.formatSummaryJson(a, stats)
            else
                try report_mod.formatSummaryText(a, stats);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        try usageAudit(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "config")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        if (std.mem.eql(u8, sub, "validate")) {
            const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
            const format = flagValue(argv, "--format") orelse if (hasFlag(argv, "--json")) "json" else "toml";

            var validated = try app.loadConfig(cfg_path);
            defer validated.deinit(a);

            if (validated.warnings.len > 0 and !std.mem.eql(u8, format, "json")) {
                var buf: [4096]u8 = undefined;
                var fw = std.Io.File.stderr().writer(io, &buf);
                for (validated.warnings) |wrn| {
                    try fw.interface.print("warning: {s}: {s}\n", .{ wrn.key_path, wrn.message });
                }
                try fw.flush();
            }

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (std.mem.eql(u8, format, "json")) {
                var tw: std.Io.Writer.Allocating = .init(a);
                defer tw.deinit();
                try validated.printNormalizedToml(a, &tw.writer);
                const normalized = try tw.toOwnedSlice();
                defer a.free(normalized);

                const out = try configValidateJsonAlloc(a, validated, normalized);
                defer a.free(out);
                try ow.interface.print("{s}\n", .{out});
            } else if (std.mem.eql(u8, format, "toml")) {
                try validated.printNormalizedToml(a, &ow.interface);
            } else {
                try validated.print(&ow.interface);
            }
            try ow.flush();
            return;
        }
        try usageConfig(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "agent")) {
        const term = @import("util/term.zig");
        const explicit_msg = flagValue(argv, "--message");
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        const verbose = hasFlag(argv, "--verbose");
        const interactive = hasFlag(argv, "--interactive");
        const agent_id = flagValue(argv, "--agent");
        const as_json = hasFlag(argv, "--json");
        const model_override = flagValue(argv, "--model");
        const preset_override = flagValue(argv, "--preset");

        // Stdin piping: if no --message and stdin is piped, read it
        const piped_msg: ?[]const u8 = if (explicit_msg == null and !interactive and !term.stdinIsTty()) blk: {
            const stdin = std.Io.File.stdin();
            var rbuf: [4096]u8 = undefined;
            var reader = stdin.reader(io, &rbuf);
            break :blk reader.interface.allocRemaining(a, std.Io.Limit.limited(1 * 1024 * 1024)) catch null;
        } else null;
        defer if (piped_msg) |pm| a.free(pm);

        const msg = explicit_msg orelse piped_msg orelse "hello";

        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        // Zero-config: auto-switch stub to openai_compat when API key is present
        applyEnvDefaults(&validated);

        // Env var overrides (lower priority than CLI flags)
        applyEnvOverrides(&validated);

        // CLI flags take highest priority
        if (model_override) |m| validated.raw.provider_primary.model = m;
        if (preset_override) |p| validated.raw.capabilities.active_preset = p;

        const trace = @import("obs/trace.zig");
        const loop = @import("agent/loop.zig");

        if (as_json) {
            if (interactive) return error.InvalidArgs;

            const rid = trace.newRequestId(io);
            var result = try loop.runLoop(a, io, validated, msg, rid.slice(), .{
                .verbose = verbose,
                .interactive = false,
                .agent_id = agent_id,
            });
            defer result.deinit(a);

            const out = if (result.attestation) |att|
                try jsonObj(a, .{
                    .request_id = rid.slice(),
                    .turns = result.turns,
                    .content = result.content,
                    .merkle_root = att.merkle_root_hex[0..],
                    .event_count = att.event_count,
                })
            else
                try jsonObj(a, .{
                    .request_id = rid.slice(),
                    .turns = result.turns,
                    .content = result.content,
                });
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
        } else {
            if (interactive) {
                try app.runAgent(validated, msg, .{
                    .verbose = verbose,
                    .interactive = true,
                    .agent_id = agent_id,
                });
                return;
            }

            // Progress indication for non-interactive, non-json runs
            {
                var ebuf: [256]u8 = undefined;
                var ew = std.Io.File.stderr().writer(io, &ebuf);
                try ew.interface.writeAll("thinking...\n");
                try ew.flush();
            }

            const rid = trace.newRequestId(io);
            var result = try loop.runLoop(a, io, validated, msg, rid.slice(), .{
                .verbose = verbose,
                .interactive = false,
                .agent_id = agent_id,
            });
            defer result.deinit(a);

            const receipt_path = try std.fmt.allocPrint(a, "{s}/.zigclaw/receipts/{s}.json", .{
                validated.raw.security.workspace_root,
                rid.slice(),
            });
            defer a.free(receipt_path);
            const capsule_path = try std.fmt.allocPrint(a, "{s}/.zigclaw/capsules/{s}.json", .{
                validated.raw.security.workspace_root,
                rid.slice(),
            });
            defer a.free(capsule_path);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("request_id={s}\nturns={d}\n{s}\n", .{ rid.slice(), result.turns, result.content });
            if (validated.raw.attestation.enabled) {
                try ow.interface.print("receipt_path={s}\n", .{receipt_path});
            }
            if (validated.raw.replay.enabled) {
                try ow.interface.print("capsule_path={s}\n", .{capsule_path});
            }
            try ow.flush();
        }
        return;
    }

    if (std.mem.eql(u8, cmd, "init")) {
        const as_json = hasFlag(argv, "--json");
        const quick = hasFlag(argv, "--quick") or hasFlag(argv, "--scaffold");
        const full = hasFlag(argv, "--full");
        const guided = hasFlag(argv, "--guided");
        if (as_json or quick) {
            try scaffoldProject(a, io, as_json, full);
        } else {
            try runOnboarding(a, io, guided, full);
        }
        return;
    }

    if (std.mem.eql(u8, cmd, "prompt")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";

        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (std.mem.eql(u8, sub, "dump")) {
            const msg = flagValue(argv, "--message") orelse "";
            const format = flagValue(argv, "--format") orelse "json";
            const out_path = flagValue(argv, "--out");

            var b = try @import("agent/bundle.zig").build(a, io, validated, msg);
            defer b.deinit(a);

            const payload = if (std.mem.eql(u8, format, "text"))
                try @import("agent/bundle.zig").dumpTextAlloc(a, b)
            else
                try @import("agent/bundle.zig").dumpJsonAlloc(a, b);
            defer a.free(payload);

            if (out_path) |p| {
                var f = try std.Io.Dir.cwd().createFile(io, p, .{ .truncate = true });
                defer f.close(io);
                var fbuf: [4096]u8 = undefined;
                var fw = f.writer(io, &fbuf);
                try fw.interface.writeAll(payload);
                try fw.interface.writeAll("\n");
                try fw.flush();
            } else {
                var obuf: [4096]u8 = undefined;
                var ow = std.Io.File.stdout().writer(io, &obuf);
                try ow.interface.print("{s}\n", .{payload});
                try ow.flush();
            }
            return;
        }

        if (std.mem.eql(u8, sub, "diff")) {
            const a_path = flagValue(argv, "--a") orelse return error.InvalidArgs;
            const b_path = flagValue(argv, "--b") orelse return error.InvalidArgs;
            const as_json = hasFlag(argv, "--json");

            const left = try std.Io.Dir.cwd().readFileAlloc(io, a_path, a, std.Io.Limit.limited(4 * 1024 * 1024));
            defer a.free(left);
            const right = try std.Io.Dir.cwd().readFileAlloc(io, b_path, a, std.Io.Limit.limited(4 * 1024 * 1024));
            defer a.free(right);

            const d = try @import("util/diff.zig").diffTextAlloc(a, left, right);
            defer a.free(d);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (as_json) {
                const out = try jsonObj(a, .{
                    .a = a_path,
                    .b = b_path,
                    .diff = d,
                });
                defer a.free(out);
                try ow.interface.print("{s}\n", .{out});
            } else {
                try ow.interface.print("{s}", .{d});
            }
            try ow.flush();
            return;
        }

        try usagePrompt(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "tools")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (std.mem.eql(u8, sub, "list")) {
            const json = try @import("tools/manifest_runtime.zig").listToolsJsonAlloc(a, io, validated.raw.tools.plugin_dir);
            defer a.free(json);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{json});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "describe")) {
            if (argv.len < 4) return error.InvalidArgs;
            const tool: []const u8 = argv[3];
            const json = try @import("tools/manifest_runtime.zig").describeToolJsonAlloc(a, io, validated.raw.tools.plugin_dir, tool);
            defer a.free(json);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{json});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "run")) {
            if (argv.len < 4) return error.InvalidArgs;
            const tool: []const u8 = argv[3];
            const args_json = flagValue(argv, "--args") orelse "{}";

            var res = try app.runTool(validated, tool, args_json);
            defer res.deinit(a);

            const out = try res.toJsonAlloc(a);
            defer a.free(out);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        try usageTools(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "task")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        const tasks = @import("primitives/tasks.zig");

        if (std.mem.eql(u8, sub, "add")) {
            const title = if (argv.len >= 4) argv[3] else (flagValue(argv, "--title") orelse return error.InvalidArgs);
            var res = try tasks.addTask(a, io, validated, .{
                .title = title,
                .status = flagValue(argv, "--status"),
                .priority = flagValue(argv, "--priority"),
                .owner = flagValue(argv, "--owner"),
                .project = flagValue(argv, "--project"),
                .tags = flagValue(argv, "--tags"),
                .due = flagValue(argv, "--due"),
                .estimate = flagValue(argv, "--estimate"),
                .parent = flagValue(argv, "--parent"),
                .depends_on = flagValue(argv, "--depends-on"),
                .body = flagValue(argv, "--body"),
                .event_id = flagValue(argv, "--event-id"),
            });
            defer res.deinit(a);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{{\"slug\":\"{s}\",\"path\":\"{s}\",\"created\":{s}}}\n", .{
                res.slug,
                res.path,
                if (res.created) "true" else "false",
            });
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "list")) {
            const format = flagValue(argv, "--format") orelse "text";
            const items = try tasks.listTasks(a, io, validated, .{
                .status = flagValue(argv, "--status"),
                .owner = flagValue(argv, "--owner"),
                .project = flagValue(argv, "--project"),
            });
            defer tasks.freeTaskSummaries(a, items);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (std.mem.eql(u8, format, "json")) {
                const json = try tasks.listJsonAlloc(a, items);
                defer a.free(json);
                try ow.interface.print("{s}\n", .{json});
            } else {
                for (items) |item| {
                    try ow.interface.print("{s}\t{s}\t{s}\n", .{ item.slug, item.status, item.title });
                }
            }
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "done")) {
            if (argv.len < 4) return error.InvalidArgs;
            const slug = argv[3];
            var item = try tasks.markTaskDone(a, io, validated, slug, flagValue(argv, "--reason"));
            defer item.deinit(a);
            const out = try tasks.summaryJsonAlloc(a, item);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        try usageTask(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "primitive")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        if (!std.mem.eql(u8, sub, "validate")) {
            try usageAll(io);
            return;
        }
        if (argv.len < 4) return error.InvalidArgs;
        const target = argv[3];
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";

        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        try @import("primitives/tasks.zig").validateTaskPrimitive(a, io, validated, target);

        var obuf: [4096]u8 = undefined;
        var ow = std.Io.File.stdout().writer(io, &obuf);
        try ow.interface.print("{{\"ok\":true,\"target\":\"{s}\"}}\n", .{target});
        try ow.flush();
        return;
    }

    if (std.mem.eql(u8, cmd, "templates")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);
        const tasks = @import("primitives/tasks.zig");

        if (std.mem.eql(u8, sub, "list")) {
            const out = try tasks.listTemplatesJsonAlloc(a, io, validated);
            defer a.free(out);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "show")) {
            const name = if (argv.len >= 4) argv[3] else "task";
            const out = try tasks.showTemplateAlloc(a, io, validated, name);
            defer a.free(out);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}", .{out});
            if (out.len == 0 or out[out.len - 1] != '\n') try ow.interface.writeAll("\n");
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "validate")) {
            const name = if (argv.len >= 4) argv[3] else "task";
            try tasks.validateTemplate(a, io, validated, name);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{{\"ok\":true,\"template\":\"{s}\"}}\n", .{name});
            try ow.flush();
            return;
        }

        try usageTemplates(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "queue")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);
        const queue_mod = @import("queue/worker.zig");

        if (std.mem.eql(u8, sub, "enqueue-agent")) {
            const msg = flagValue(argv, "--message") orelse return error.InvalidArgs;
            const agent_id = flagValue(argv, "--agent");
            const request_id = flagValue(argv, "--request-id");

            const rid = try queue_mod.enqueueAgent(a, io, validated, msg, agent_id, request_id);
            defer a.free(rid);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{{\"request_id\":\"{s}\",\"queued\":true}}\n", .{rid});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "worker")) {
            const once = hasFlag(argv, "--once");
            const max_jobs = if (flagValue(argv, "--max-jobs")) |m| try std.fmt.parseInt(usize, m, 10) else null;
            const poll_ms = if (flagValue(argv, "--poll-ms")) |m| try std.fmt.parseInt(u32, m, 10) else null;

            try queue_mod.runWorker(a, io, validated, .{
                .once = once,
                .max_jobs = max_jobs,
                .poll_ms_override = poll_ms,
            });
            return;
        }

        if (std.mem.eql(u8, sub, "status")) {
            const rid = flagValue(argv, "--request-id") orelse return error.InvalidArgs;
            const include_payload = hasFlag(argv, "--include-payload");
            const out = try queue_mod.statusJsonAlloc(a, io, validated, rid, include_payload);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "watch")) {
            const rid = flagValue(argv, "--request-id") orelse return error.InvalidArgs;
            const include_payload = hasFlag(argv, "--include-payload");
            const as_json = hasFlag(argv, "--json");
            const poll_ms: u32 = if (flagValue(argv, "--poll-ms")) |m| try std.fmt.parseInt(u32, m, 10) else 1000;
            const timeout_ms: ?u64 = if (flagValue(argv, "--timeout-ms")) |t| try std.fmt.parseInt(u64, t, 10) else null;
            const start_ms = nowUnixMs(io);
            var last_state: ?[]u8 = null;
            defer if (last_state) |s| a.free(s);

            while (true) {
                const out = try queue_mod.statusJsonAlloc(a, io, validated, rid, include_payload);
                defer a.free(out);

                var parsed = try std.json.parseFromSlice(std.json.Value, a, out, .{});
                defer parsed.deinit();
                if (parsed.value != .object) return error.InvalidJson;
                const state_v = parsed.value.object.get("state") orelse return error.InvalidJson;
                if (state_v != .string) return error.InvalidJson;
                const state = state_v.string;

                const changed = blk: {
                    if (last_state == null) break :blk true;
                    break :blk !std.mem.eql(u8, last_state.?, state);
                };
                if (changed) {
                    if (last_state) |s| a.free(s);
                    last_state = try a.dupe(u8, state);

                    var obuf: [4096]u8 = undefined;
                    var ow = std.Io.File.stdout().writer(io, &obuf);
                    const ts_ms = nowUnixMs(io);
                    if (as_json) {
                        const event = try queueWatchEventJsonAlloc(a, rid, state, ts_ms, parsed.value);
                        defer a.free(event);
                        try ow.interface.print("{s}\n", .{event});
                    } else {
                        try ow.interface.print("state={s} ts_ms={d}\n{s}\n", .{ state, ts_ms, out });
                    }
                    try ow.flush();
                }

                if (std.mem.eql(u8, state, "completed") or std.mem.eql(u8, state, "canceled") or std.mem.eql(u8, state, "not_found")) {
                    break;
                }

                if (timeout_ms) |limit| {
                    if (@as(u64, @intCast(nowUnixMs(io) - start_ms)) >= limit) break;
                }
                io.sleep(std.Io.Duration.fromMilliseconds(@intCast(poll_ms)), .awake) catch {};
            }
            return;
        }

        if (std.mem.eql(u8, sub, "cancel")) {
            const rid = flagValue(argv, "--request-id") orelse return error.InvalidArgs;
            const out = try queue_mod.cancelRequestJsonAlloc(a, io, validated, rid);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "metrics")) {
            const out = try queue_mod.metricsJsonAlloc(a, io, validated);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        try usageQueue(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "git")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        const git_sync = @import("persistence/git_sync.zig");
        const as_json = hasFlag(argv, "--json");

        if (std.mem.eql(u8, sub, "status")) {
            var st = try git_sync.status(a, io, validated);
            defer st.deinit(a);

            const out = try git_sync.statusJsonAlloc(a, st);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (as_json) {
                try ow.interface.print("{s}\n", .{out});
            } else {
                try ow.interface.print("repo_ok={s} remote_configured={s} syncable={d} ignored={d}\n", .{
                    if (st.repo_ok) "true" else "false",
                    if (st.remote_configured) "true" else "false",
                    st.syncable_paths.len,
                    st.ignored_paths.len,
                });
                for (st.syncable_paths) |p| try ow.interface.print("syncable: {s}\n", .{p});
                for (st.ignored_paths) |p| try ow.interface.print("ignored: {s}\n", .{p});
            }
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "sync")) {
            var res = try git_sync.sync(a, io, validated, .{
                .message = flagValue(argv, "--message"),
                .push = hasFlag(argv, "--push"),
            });
            defer res.deinit(a);

            const out = try git_sync.syncJsonAlloc(a, res);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (as_json) {
                try ow.interface.print("{s}\n", .{out});
            } else {
                try ow.interface.print(
                    "noop={s} committed={s} pushed={s} syncable={d} ignored={d}",
                    .{
                        if (res.noop) "true" else "false",
                        if (res.committed) "true" else "false",
                        if (res.pushed) "true" else "false",
                        res.syncable_count,
                        res.ignored_count,
                    },
                );
                if (res.commit_hash) |h| try ow.interface.print(" commit={s}", .{h});
                try ow.interface.writeAll("\n");
            }
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "init")) {
            var init_res = try git_sync.initRepo(a, io, validated, .{
                .remote = flagValue(argv, "--remote"),
                .branch = flagValue(argv, "--branch"),
            });
            defer init_res.deinit(a);

            const out = try git_sync.initJsonAlloc(a, init_res);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (as_json) {
                try ow.interface.print("{s}\n", .{out});
            } else {
                try ow.interface.print("repo_ready={s} remote_configured={s} branch={s}\n", .{
                    if (init_res.repo_ready) "true" else "false",
                    if (init_res.remote_configured) "true" else "false",
                    init_res.branch,
                });
            }
            try ow.flush();
            return;
        }

        try usageGit(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "policy")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (std.mem.eql(u8, sub, "hash")) {
            const as_json = hasFlag(argv, "--json");
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (as_json) {
                const out = try jsonObj(a, .{
                    .policy_hash = validated.policy.policyHash(),
                });
                defer a.free(out);
                try ow.interface.print("{s}\n", .{out});
            } else {
                try ow.interface.print("{s}\n", .{validated.policy.policyHash()});
            }
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "explain")) {
            const tool = flagValue(argv, "--tool");
            const mount = flagValue(argv, "--mount");
            const command = flagValue(argv, "--command");

            var selected: u8 = 0;
            if (tool != null) selected += 1;
            if (mount != null) selected += 1;
            if (command != null) selected += 1;
            if (selected != 1) return error.InvalidArgs;

            const json = if (tool) |t|
                try validated.policy.explainToolJsonAlloc(a, t)
            else if (mount) |m|
                try validated.policy.explainMountJsonAlloc(a, m)
            else
                try validated.policy.explainCommandJsonAlloc(a, command.?);
            defer a.free(json);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{json});
            try ow.flush();
            return;
        }

        try usagePolicy(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "attest")) {
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (argv.len >= 3 and std.mem.eql(u8, argv[2], "verify")) {
            const rid = flagValue(argv, "--request-id") orelse return error.InvalidArgs;
            const event_index_s = flagValue(argv, "--event-index") orelse return error.InvalidArgs;
            const event_index = try std.fmt.parseInt(usize, event_index_s, 10);

            const receipt_json = try @import("attestation/receipt.zig").readReceiptJsonAlloc(
                a,
                io,
                validated.raw.security.workspace_root,
                rid,
            );
            defer a.free(receipt_json);

            const out = try @import("attestation/receipt.zig").verifyEventFromReceiptJsonAlloc(a, receipt_json, event_index);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        if (argv.len < 3) return error.InvalidArgs;
        const rid = argv[2];
        const receipt_json = try @import("attestation/receipt.zig").readReceiptJsonAlloc(
            a,
            io,
            validated.raw.security.workspace_root,
            rid,
        );
        defer a.free(receipt_json);

        var obuf: [4096]u8 = undefined;
        var ow = std.Io.File.stdout().writer(io, &obuf);
        try ow.interface.print("{s}\n", .{receipt_json});
        try ow.flush();
        return;
    }

    if (std.mem.eql(u8, cmd, "replay")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";

        if (std.mem.eql(u8, sub, "capture")) {
            const rid = flagValue(argv, "--request-id") orelse return error.InvalidArgs;
            const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
            var validated = try app.loadConfig(cfg_path);
            defer validated.deinit(a);

            const capsule_json = try @import("replay/capsule.zig").readCapsuleJsonAlloc(
                a,
                io,
                validated.raw.security.workspace_root,
                rid,
            );
            defer a.free(capsule_json);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{capsule_json});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "run")) {
            const capsule_path = flagValue(argv, "--capsule") orelse return error.InvalidArgs;
            const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";

            var validated = try app.loadConfig(cfg_path);
            defer validated.deinit(a);

            const capsule_json = try std.Io.Dir.cwd().readFileAlloc(io, capsule_path, a, std.Io.Limit.limited(8 * 1024 * 1024));
            defer a.free(capsule_json);

            var seed = try @import("replay/replayer.zig").extractRunSeedAlloc(a, capsule_json);
            defer seed.deinit(a);

            var vcq = validated;
            vcq.raw.provider_fixtures.mode = .capsule_replay;
            vcq.raw.provider_fixtures.capsule_path = capsule_path;
            vcq.raw.provider_reliable.retries = 0;

            var result = try @import("agent/loop.zig").runLoop(
                a,
                io,
                vcq,
                seed.message,
                seed.request_id,
                .{ .delegate_depth = 1 },
            );
            defer result.deinit(a);

            const out = try jsonObj(a, .{
                .request_id = seed.request_id,
                .content = result.content,
                .turns = result.turns,
                .replayed = true,
            });
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "diff")) {
            const a_path = flagValue(argv, "--a") orelse return error.InvalidArgs;
            const b_path = flagValue(argv, "--b") orelse return error.InvalidArgs;

            const left = try std.Io.Dir.cwd().readFileAlloc(io, a_path, a, std.Io.Limit.limited(8 * 1024 * 1024));
            defer a.free(left);
            const right = try std.Io.Dir.cwd().readFileAlloc(io, b_path, a, std.Io.Limit.limited(8 * 1024 * 1024));
            defer a.free(right);

            const out = try @import("replay/diff.zig").diffCapsulesJsonAlloc(a, left, right);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        try usageReplay(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "gateway")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "start";
        if (!std.mem.eql(u8, sub, "start")) {
            try usageGateway(io);
            return;
        }

        const bind = flagValue(argv, "--bind") orelse "127.0.0.1";
        const port_s = flagValue(argv, "--port") orelse "8787";
        const port = try std.fmt.parseInt(u16, port_s, 10);

        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        try @import("gateway/server.zig").start(a, io, &app, validated, bind, port);
        return;
    }

    try unknownCommand(io, cmd);
}

const known_commands = [_][]const u8{
    "version",   "doctor",  "setup",     "update",    "chat",
    "agent",     "init",    "run",       "ops",       "vault",
    "config",    "prompt",  "tools",     "task",      "primitive",
    "templates", "queue",   "git",       "policy",    "audit",
    "attest",    "replay",  "gateway",   "completion",
};

fn unknownCommand(io: std.Io, cmd: []const u8) !void {
    const term = @import("util/term.zig");
    const color = term.stderrSupportsColor();
    var ebuf: [1024]u8 = undefined;
    var ew = std.Io.File.stderr().writer(io, &ebuf);

    try term.writeStyled(&ew.interface, .red, "error:", color);
    try ew.interface.print(" unknown command '{s}'\n", .{cmd});

    var best: ?[]const u8 = null;
    var best_dist: usize = 3; // suggest only if distance <= 2
    for (&known_commands) |kc| {
        const d = levenshtein(cmd, kc);
        if (d < best_dist) {
            best_dist = d;
            best = kc;
        }
    }

    if (best) |suggestion| {
        try term.writeStyled(&ew.interface, .yellow, "hint:", color);
        try ew.interface.print(" did you mean '{s}'?\n", .{suggestion});
    }

    try ew.interface.writeAll("Run 'zigclaw --help' for available commands.\n");
    try ew.flush();
}

fn levenshtein(a_str: []const u8, b_str: []const u8) usize {
    if (a_str.len == 0) return b_str.len;
    if (b_str.len == 0) return a_str.len;
    if (b_str.len > 32) return b_str.len; // bail on long strings

    var prev_row: [33]usize = undefined;
    for (0..b_str.len + 1) |i| prev_row[i] = i;

    for (a_str, 0..) |a_ch, i| {
        var cur_row: [33]usize = undefined;
        cur_row[0] = i + 1;
        for (b_str, 0..) |b_ch, j| {
            const cost: usize = if (a_ch == b_ch) 0 else 1;
            cur_row[j + 1] = @min(@min(
                cur_row[j] + 1,
                prev_row[j + 1] + 1,
            ), prev_row[j] + cost);
        }
        prev_row = cur_row;
    }
    return prev_row[b_str.len];
}

fn flagValue(argv: []const [:0]const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 1 < argv.len) : (i += 1) {
        if (std.mem.eql(u8, argv[i], name)) return argv[i + 1];
    }
    return null;
}

fn hasFlag(argv: []const [:0]const u8, name: []const u8) bool {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, name)) return true;
    }
    return false;
}

fn isHelpArg(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h");
}

fn nowUnixMs(io: std.Io) i64 {
    const ts = std.Io.Clock.now(.real, io);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}

fn jsonObj(a: std.mem.Allocator, value: anytype) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.write(value);
    return try aw.toOwnedSlice();
}

fn configValidateJsonAlloc(a: std.mem.Allocator, validated: config_mod.ValidatedConfig, normalized_toml: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("ok");
    try stream.write(true);
    try stream.objectField("policy_hash");
    try stream.write(validated.policy.policyHash());
    try stream.objectField("warnings");
    try stream.beginArray();
    for (validated.warnings) |w| {
        try stream.beginObject();
        try stream.objectField("key_path");
        try stream.write(w.key_path);
        try stream.objectField("message");
        try stream.write(w.message);
        try stream.endObject();
    }
    try stream.endArray();
    try stream.objectField("normalized_toml");
    try stream.write(normalized_toml);
    try stream.endObject();

    return try aw.toOwnedSlice();
}

fn runOnboarding(a: std.mem.Allocator, io: std.Io, guided: bool, full: bool) !void {
    if (guided) {
        const completed = try @import("setup/wizard.zig").run(a, io);
        if (!completed) return;
    } else {
        try scaffoldProject(a, io, false, full);
    }

    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.writeAll("\nRunning post-setup checks...\n");
    try ow.flush();

    doctor.run(a, io, "zigclaw.toml", false) catch |e| {
        var ebuf: [1024]u8 = undefined;
        var ew = std.Io.File.stderr().writer(io, &ebuf);
        try ew.interface.print("warning: doctor check failed: {s}\n", .{@errorName(e)});
        try ew.flush();
    };

    if (!guided) {
        try ow.interface.writeAll("Tip: build plugins with `zig build plugins`\n");
        try ow.flush();
        return;
    }

    const prompts = @import("setup/prompts.zig");
    const should_build = try prompts.readYesNo(io, "Build plugins now (zig build plugins)?", true);
    if (!should_build) return;

    try ow.interface.writeAll("Building plugins...\n");
    try ow.flush();
    runPluginBuild(a, io) catch |e| {
        var ebuf: [1024]u8 = undefined;
        var ew = std.Io.File.stderr().writer(io, &ebuf);
        try ew.interface.print("warning: plugin build failed: {s}\n", .{@errorName(e)});
        try ew.interface.writeAll("hint: run `zig build plugins` after fixing build issues\n");
        try ew.flush();
    };
}

fn runPluginBuild(a: std.mem.Allocator, io: std.Io) !void {
    const argv = [_][]const u8{ "zig", "build", "plugins" };
    var child = try std.process.spawn(io, .{
        .argv = &argv,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    var stdout_text: []u8 = &.{};
    errdefer if (stdout_text.len > 0) a.free(stdout_text);
    var stderr_text: []u8 = &.{};
    errdefer if (stderr_text.len > 0) a.free(stderr_text);

    if (child.stdout) |*out| {
        var out_buf: [4096]u8 = undefined;
        var out_reader = out.reader(io, &out_buf);
        stdout_text = try out_reader.interface.allocRemaining(a, std.Io.Limit.limited(8 * 1024 * 1024));
    } else {
        stdout_text = try a.dupe(u8, "");
    }

    if (child.stderr) |*errf| {
        var err_buf: [4096]u8 = undefined;
        var err_reader = errf.reader(io, &err_buf);
        stderr_text = try err_reader.interface.allocRemaining(a, std.Io.Limit.limited(8 * 1024 * 1024));
    } else {
        stderr_text = try a.dupe(u8, "");
    }

    const term = try child.wait(io);

    if (stdout_text.len > 0) {
        var obuf: [4096]u8 = undefined;
        var ow = std.Io.File.stdout().writer(io, &obuf);
        try ow.interface.writeAll(stdout_text);
        if (stdout_text[stdout_text.len - 1] != '\n') try ow.interface.writeAll("\n");
        try ow.flush();
    }

    if (stderr_text.len > 0) {
        var ebuf: [4096]u8 = undefined;
        var ew = std.Io.File.stderr().writer(io, &ebuf);
        try ew.interface.writeAll(stderr_text);
        if (stderr_text[stderr_text.len - 1] != '\n') try ew.interface.writeAll("\n");
        try ew.flush();
    }

    a.free(stdout_text);
    a.free(stderr_text);

    switch (term) {
        .exited => |code| if (code != 0) return error.PluginBuildFailed,
        else => return error.PluginBuildFailed,
    }
}

fn completionScript(shell: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, shell, "zsh")) {
        return 
        \\#compdef zigclaw
        \\
        \\_zigclaw() {
        \\  local -a cmds
        \\  cmds=(
        \\    'version:Show binary version'
        \\    'doctor:Run environment diagnostics'
        \\    'setup:Run guided onboarding'
        \\    'update:Check or apply updates'
        \\    'chat:Interactive agent session'
        \\    'run:Run-related helpers'
        \\    'ops:Operations dashboard helpers'
        \\    'vault:Manage encrypted secrets'
        \\    'init:Initialize workspace files'
        \\    'agent:Run agent loop'
        \\    'prompt:Prompt inspection tools'
        \\    'tools:Tool registry commands'
        \\    'task:Task primitive commands'
        \\    'primitive:Primitive validation'
        \\    'templates:Template commands'
        \\    'git:Persistence git commands'
        \\    'queue:Queue worker commands'
        \\    'config:Configuration commands'
        \\    'policy:Policy commands'
        \\    'audit:Audit commands'
        \\    'attest:Attestation commands'
        \\    'replay:Replay commands'
        \\    'gateway:Gateway server commands'
        \\    'completion:Shell completions'
        \\  )
        \\  _arguments \
        \\    '1:command:->cmds' \
        \\    '2:subcommand:->subs' \
        \\    '*::args:_files'
        \\
        \\  case $state in
        \\    cmds)
        \\      _describe -t commands 'zigclaw commands' cmds
        \\      ;;
        \\    subs)
        \\      case ${words[2]} in
        \\        queue) _values 'queue subcommand' enqueue-agent worker status watch cancel metrics ;;
        \\        vault) _values 'vault subcommand' set get list delete ;;
        \\        run) _values 'run subcommand' summary ;;
        \\        ops) _values 'ops subcommand' summary watch ;;
        \\        completion) _values 'shell' zsh bash fish ;;
        \\      esac
        \\      ;;
        \\  esac
        \\}
        \\
        \\_zigclaw "$@"
        ;
    }

    if (std.mem.eql(u8, shell, "bash")) {
        return 
        \\_zigclaw_completions()
        \\{
        \\  local cur="${COMP_WORDS[COMP_CWORD]}"
        \\  local prev="${COMP_WORDS[COMP_CWORD-1]}"
        \\  local cmd="${COMP_WORDS[1]}"
        \\
        \\  local cmds="version doctor setup update chat run ops vault init agent prompt tools task primitive templates git queue config policy audit attest replay gateway completion"
        \\  if [[ ${COMP_CWORD} -eq 1 ]]; then
        \\    COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
        \\    return
        \\  fi
        \\
        \\  case "${cmd}" in
        \\    queue)
        \\      COMPREPLY=( $(compgen -W "enqueue-agent worker status watch cancel metrics" -- "$cur") )
        \\      return
        \\      ;;
        \\    vault)
        \\      COMPREPLY=( $(compgen -W "set get list delete" -- "$cur") )
        \\      return
        \\      ;;
        \\    run)
        \\      COMPREPLY=( $(compgen -W "summary" -- "$cur") )
        \\      return
        \\      ;;
        \\    ops)
        \\      COMPREPLY=( $(compgen -W "summary watch" -- "$cur") )
        \\      return
        \\      ;;
        \\    completion)
        \\      COMPREPLY=( $(compgen -W "zsh bash fish" -- "$cur") )
        \\      return
        \\      ;;
        \\  esac
        \\
        \\  COMPREPLY=( $(compgen -W "--help -h --json --config --request-id --message --format --poll-ms --timeout-ms --include-payload --agent --verbose --interactive" -- "$cur") )
        \\}
        \\
        \\complete -F _zigclaw_completions zigclaw
        ;
    }

    if (std.mem.eql(u8, shell, "fish")) {
        return 
        \\complete -c zigclaw -f
        \\complete -c zigclaw -n '__fish_use_subcommand' -a 'version doctor setup update chat run ops vault init agent prompt tools task primitive templates git queue config policy audit attest replay gateway completion'
        \\complete -c zigclaw -n '__fish_seen_subcommand_from queue' -a 'enqueue-agent worker status watch cancel metrics'
        \\complete -c zigclaw -n '__fish_seen_subcommand_from vault' -a 'set get list delete'
        \\complete -c zigclaw -n '__fish_seen_subcommand_from run' -a 'summary'
        \\complete -c zigclaw -n '__fish_seen_subcommand_from ops' -a 'summary watch'
        \\complete -c zigclaw -n '__fish_seen_subcommand_from completion' -a 'zsh bash fish'
        ;
    }

    return null;
}

fn queueWatchEventJsonAlloc(
    a: std.mem.Allocator,
    request_id: []const u8,
    state: []const u8,
    ts_ms: i64,
    status: std.json.Value,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("state");
    try stream.write(state);
    try stream.objectField("ts_ms");
    try stream.write(ts_ms);
    try stream.objectField("status");
    try stream.write(status);
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn printRunSummary(a: std.mem.Allocator, io: std.Io, validated: config_mod.ValidatedConfig, request_id: []const u8, as_json: bool) !void {
    const queue_mod = @import("queue/worker.zig");
    const status = try queue_mod.statusJsonAlloc(a, io, validated, request_id, false);
    defer a.free(status);

    var parsed = try std.json.parseFromSlice(std.json.Value, a, status, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJson;
    const state_v = parsed.value.object.get("state") orelse return error.InvalidJson;
    if (state_v != .string) return error.InvalidJson;
    const state = state_v.string;

    const receipt_path = try std.fmt.allocPrint(a, "{s}/.zigclaw/receipts/{s}.json", .{
        validated.raw.security.workspace_root,
        request_id,
    });
    defer a.free(receipt_path);
    const capsule_path = try std.fmt.allocPrint(a, "{s}/.zigclaw/capsules/{s}.json", .{
        validated.raw.security.workspace_root,
        request_id,
    });
    defer a.free(capsule_path);

    const receipt_exists = if (std.Io.Dir.cwd().statFile(io, receipt_path, .{})) |_| true else |_| false;
    const capsule_exists = if (std.Io.Dir.cwd().statFile(io, capsule_path, .{})) |_| true else |_| false;

    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    if (as_json) {
        const out = try jsonObj(a, .{
            .request_id = request_id,
            .state = state,
            .receipt_path = receipt_path,
            .receipt_exists = receipt_exists,
            .capsule_path = capsule_path,
            .capsule_exists = capsule_exists,
        });
        defer a.free(out);
        try ow.interface.print("{s}\n", .{out});
    } else {
        try ow.interface.print("request_id={s}\nstate={s}\n", .{ request_id, state });
        try ow.interface.print("receipt_path={s} ({s})\n", .{ receipt_path, if (receipt_exists) "found" else "missing" });
        try ow.interface.print("capsule_path={s} ({s})\n", .{ capsule_path, if (capsule_exists) "found" else "missing" });
        try ow.interface.print("watch=zigclaw queue watch --request-id {s}\n", .{request_id});
    }
    try ow.flush();
}

fn printOpsSnapshot(a: std.mem.Allocator, io: std.Io, validated: config_mod.ValidatedConfig, limit: usize, as_json: bool) !void {
    const snapshot = try opsSnapshotJsonAlloc(a, io, validated, limit);
    defer a.free(snapshot);

    var obuf: [8192]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    if (as_json) {
        try ow.interface.print("{s}\n", .{snapshot});
        try ow.flush();
        return;
    }

    var parsed = try std.json.parseFromSlice(std.json.Value, a, snapshot, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJson;
    const root = parsed.value.object;

    const now_ms = getJsonInt(root, "generated_at_ms") orelse 0;
    const queue_v = root.get("queue") orelse return error.InvalidJson;
    if (queue_v != .object) return error.InvalidJson;
    const queue = queue_v.object;

    const audit_v = root.get("audit_summary") orelse return error.InvalidJson;
    if (audit_v != .object) return error.InvalidJson;
    const audit = audit_v.object;

    try ow.interface.print("zigclaw ops dashboard @ {d}\n", .{now_ms});
    try ow.interface.writeAll("========================================\n");
    try ow.interface.print(
        "queue: incoming {d} (ready {d}, delayed {d}) | processing {d} | outgoing {d} | canceled {d} | cancel_markers {d}\n",
        .{
            getJsonInt(queue, "incoming_total") orelse 0,
            getJsonInt(queue, "incoming_ready") orelse 0,
            getJsonInt(queue, "incoming_delayed") orelse 0,
            getJsonInt(queue, "processing") orelse 0,
            getJsonInt(queue, "outgoing") orelse 0,
            getJsonInt(queue, "canceled") orelse 0,
            getJsonInt(queue, "cancel_markers") orelse 0,
        },
    );

    try ow.interface.print(
        "audit: total {d} | allowed {d} | denied {d} | unique decisions {d}\n",
        .{
            getJsonInt(audit, "total_events") orelse 0,
            getJsonInt(audit, "allowed_count") orelse 0,
            getJsonInt(audit, "denied_count") orelse 0,
            getJsonInt(audit, "unique_tools") orelse 0,
        },
    );

    try ow.interface.writeAll("recent receipts:\n");
    if (root.get("recent_receipts")) |receipts| {
        if (receipts == .array and receipts.array.items.len > 0) {
            for (receipts.array.items) |entry| {
                if (entry != .string) continue;
                try ow.interface.print("  - {s}\n", .{entry.string});
            }
        } else {
            try ow.interface.writeAll("  (none)\n");
        }
    } else {
        try ow.interface.writeAll("  (none)\n");
    }

    try ow.interface.writeAll("recent capsules:\n");
    if (root.get("recent_capsules")) |capsules| {
        if (capsules == .array and capsules.array.items.len > 0) {
            for (capsules.array.items) |entry| {
                if (entry != .string) continue;
                try ow.interface.print("  - {s}\n", .{entry.string});
            }
        } else {
            try ow.interface.writeAll("  (none)\n");
        }
    } else {
        try ow.interface.writeAll("  (none)\n");
    }
    try ow.flush();
}

fn opsSnapshotJsonAlloc(a: std.mem.Allocator, io: std.Io, validated: config_mod.ValidatedConfig, limit: usize) ![]u8 {
    const queue_mod = @import("queue/worker.zig");
    const report_mod = @import("audit/report.zig");
    const log_reader = @import("audit/log_reader.zig");

    const queue_json = try queue_mod.metricsJsonAlloc(a, io, validated);
    defer a.free(queue_json);
    var queue_parsed = try std.json.parseFromSlice(std.json.Value, a, queue_json, .{});
    defer queue_parsed.deinit();

    const events = try log_reader.readEvents(a, io, validated.raw.logging.dir, validated.raw.logging.file, .{});
    defer log_reader.freeEvents(a, events);
    var summary = try report_mod.buildSummary(a, events);
    defer summary.deinit(a);
    const audit_json = try report_mod.formatSummaryJson(a, summary);
    defer a.free(audit_json);
    var audit_parsed = try std.json.parseFromSlice(std.json.Value, a, audit_json, .{});
    defer audit_parsed.deinit();

    const receipts_dir = try std.fs.path.join(a, &.{ validated.raw.security.workspace_root, ".zigclaw/receipts" });
    defer a.free(receipts_dir);
    const capsules_dir = try std.fs.path.join(a, &.{ validated.raw.security.workspace_root, ".zigclaw/capsules" });
    defer a.free(capsules_dir);

    const receipts = try listRecentJsonNamesAlloc(a, io, receipts_dir, limit);
    defer freeStringList(a, receipts);
    const capsules = try listRecentJsonNamesAlloc(a, io, capsules_dir, limit);
    defer freeStringList(a, capsules);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("generated_at_ms");
    try stream.write(nowUnixMs(io));
    try stream.objectField("queue");
    try stream.write(queue_parsed.value);
    try stream.objectField("audit_summary");
    try stream.write(audit_parsed.value);
    try stream.objectField("recent_receipts");
    try stream.write(receipts);
    try stream.objectField("recent_capsules");
    try stream.write(capsules);
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn listRecentJsonNamesAlloc(a: std.mem.Allocator, io: std.Io, dir_path: []const u8, limit: usize) ![]const []const u8 {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch {
        return try a.alloc([]const u8, 0);
    };
    defer dir.close(io);

    var names = std.array_list.Managed([]const u8).init(a);
    defer names.deinit();

    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!std.mem.endsWith(u8, ent.name, ".json")) continue;
        try names.append(try a.dupe(u8, ent.name));
    }

    std.sort.block([]const u8, names.items, {}, struct {
        fn gt(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.order(u8, lhs, rhs) == .gt;
        }
    }.gt);

    const take = @min(limit, names.items.len);
    const out = try a.alloc([]const u8, take);
    for (0..take) |i| out[i] = names.items[i];
    for (take..names.items.len) |i| a.free(names.items[i]);
    return out;
}

fn freeStringList(a: std.mem.Allocator, items: []const []const u8) void {
    for (items) |it| a.free(it);
    a.free(items);
}

fn getJsonInt(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}

fn usageAgent(io: std.Io) !void {
    try writeGroupHelp(io,
        \\agent
        \\Usage:
        \\  zigclaw agent --message "..." [--verbose] [--interactive] [--agent id] [--model m] [--preset p] [--config zigclaw.toml] [--json]
        \\
        \\Examples:
        \\  zigclaw agent --message "Summarize repo status" --config zigclaw.toml
        \\  zigclaw agent --message "hello" --agent planner --json
        \\  zigclaw agent --interactive --config zigclaw.toml
        \\  zigclaw agent --message "hello" --model gpt-4.1 --preset readonly
        \\
        \\Related:
        \\  zigclaw chat --help
        \\  zigclaw prompt --help
        \\  zigclaw policy --help
    );
}

fn usageChat(io: std.Io) !void {
    try writeGroupHelp(io,
        \\chat
        \\Usage:
        \\  zigclaw chat                        Interactive session
        \\  zigclaw chat "message"              One-shot with positional argument
        \\  zigclaw chat --message "..."         One-shot with flag
        \\  echo "msg" | zigclaw chat           One-shot from stdin pipe
        \\
        \\Flags:
        \\  --agent id      Use a specific agent profile
        \\  --model m       Override configured model
        \\  --preset p      Override active capability preset
        \\  --config path   Config file (default: zigclaw.toml)
        \\  --json          JSON output (incompatible with interactive)
        \\  --verbose       Verbose logging
        \\
        \\Examples:
        \\  zigclaw chat
        \\  zigclaw chat "What time is it?"
        \\  zigclaw chat --model gpt-4.1 --preset dev "Write a test"
        \\  echo "Summarize this file" | zigclaw chat
        \\
        \\Related:
        \\  zigclaw agent --help
        \\  zigclaw prompt --help
    );
}

fn usageDoctor(io: std.Io) !void {
    try writeGroupHelp(io,
        \\doctor
        \\Usage:
        \\  zigclaw doctor [--config zigclaw.toml] [--json]
        \\
        \\Examples:
        \\  zigclaw doctor
        \\  zigclaw doctor --config zigclaw.toml --json
        \\
        \\Related:
        \\  zigclaw config --help
        \\  zigclaw init --help
    );
}

fn usageUpdate(io: std.Io) !void {
    try writeGroupHelp(io,
        \\update
        \\Usage:
        \\  zigclaw update [--check] [--url <manifest-url>] [--json]
        \\
        \\Examples:
        \\  zigclaw update --check
        \\  zigclaw update --url https://example.com/latest.json
        \\  zigclaw update --check --json
        \\
        \\Related:
        \\  zigclaw version --json
        \\  zigclaw doctor --help
    );
}

fn usageRun(io: std.Io) !void {
    try writeGroupHelp(io,
        \\run
        \\Usage:
        \\  zigclaw run summary --request-id <id> [--config zigclaw.toml] [--json]
        \\
        \\Examples:
        \\  zigclaw run summary --request-id req_1
        \\  zigclaw run summary --request-id req_1 --json
        \\  zigclaw run summary --request-id req_1 --config zigclaw.toml
        \\
        \\Related:
        \\  zigclaw queue watch --request-id <id>
        \\  zigclaw attest <request_id>
    );
}

fn usageOps(io: std.Io) !void {
    try writeGroupHelp(io,
        \\ops
        \\Usage:
        \\  zigclaw ops summary [--format text|json] [--limit N] [--config zigclaw.toml]
        \\  zigclaw ops watch [--format text|json] [--limit N] [--poll-ms N] [--iterations N] [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw ops summary
        \\  zigclaw ops summary --format json --limit 10
        \\  zigclaw ops watch --poll-ms 1000 --iterations 20
        \\
        \\Related:
        \\  zigclaw queue metrics
        \\  zigclaw audit summary --format json
    );
}

fn usageVault(io: std.Io) !void {
    try writeGroupHelp(io,
        \\vault
        \\Usage:
        \\  zigclaw vault set <name> [--vault <path>] [--json]
        \\  zigclaw vault get <name> [--vault <path>] [--json]
        \\  zigclaw vault list [--vault <path>] [--json]
        \\  zigclaw vault delete <name> [--vault <path>] [--json]
        \\
        \\Examples:
        \\  zigclaw vault set openai_api_key --vault ./.zigclaw/vault.enc
        \\  zigclaw vault get openai_api_key --json
        \\  zigclaw vault list
        \\
        \\Related:
        \\  zigclaw setup --help
        \\  zigclaw doctor --help
    );
}

fn usageConfig(io: std.Io) !void {
    try writeGroupHelp(io,
        \\config
        \\Usage:
        \\  zigclaw config validate [--config zigclaw.toml] [--format toml|text|json] [--json]
        \\
        \\Examples:
        \\  zigclaw config validate --format toml
        \\  zigclaw config validate --format json
        \\  zigclaw config validate --json
        \\
        \\Related:
        \\  zigclaw policy --help
        \\  zigclaw doctor --help
    );
}

fn usagePrompt(io: std.Io) !void {
    try writeGroupHelp(io,
        \\prompt
        \\Usage:
        \\  zigclaw prompt dump --message "..." [--format json|text] [--out path] [--config zigclaw.toml]
        \\  zigclaw prompt diff --a file --b file [--json]
        \\
        \\Examples:
        \\  zigclaw prompt dump --message "hello" --format json
        \\  zigclaw prompt dump --message "hello" --format text --out /tmp/prompt.txt
        \\  zigclaw prompt diff --a /tmp/a.txt --b /tmp/b.txt --json
        \\
        \\Related:
        \\  zigclaw agent --help
        \\  zigclaw policy --help
    );
}

fn usageTools(io: std.Io) !void {
    try writeGroupHelp(io,
        \\tools
        \\Usage:
        \\  zigclaw tools list [--config zigclaw.toml]
        \\  zigclaw tools describe <tool> [--config zigclaw.toml]
        \\  zigclaw tools run <tool> --args '{}' [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw tools list
        \\  zigclaw tools describe echo
        \\  zigclaw tools run echo --args '{"text":"hi"}'
        \\
        \\Related:
        \\  zigclaw policy --help
        \\  zigclaw doctor --help
    );
}

fn usageTask(io: std.Io) !void {
    try writeGroupHelp(io,
        \\task
        \\Usage:
        \\  zigclaw task add "..." [--priority p] [--owner o] [--project p] [--tags "a,b"] [--status s] [--config zigclaw.toml]
        \\  zigclaw task list [--status s] [--owner o] [--project p] [--format text|json] [--config zigclaw.toml]
        \\  zigclaw task done <slug> [--reason "..."] [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw task add "Reply to client" --priority high
        \\  zigclaw task list --status open --format json
        \\  zigclaw task done reply-to-client --reason "sent update"
        \\
        \\Related:
        \\  zigclaw templates --help
        \\  zigclaw git --help
    );
}

fn usageTemplates(io: std.Io) !void {
    try writeGroupHelp(io,
        \\templates
        \\Usage:
        \\  zigclaw templates list [--config zigclaw.toml]
        \\  zigclaw templates show [task] [--config zigclaw.toml]
        \\  zigclaw templates validate [task] [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw templates list
        \\  zigclaw templates show task
        \\  zigclaw templates validate task
        \\
        \\Related:
        \\  zigclaw task --help
        \\  zigclaw primitive validate <slug|path>
    );
}

fn usageQueue(io: std.Io) !void {
    try writeGroupHelp(io,
        \\queue
        \\Usage:
        \\  zigclaw queue enqueue-agent --message "..." [--agent id] [--request-id id] [--config zigclaw.toml]
        \\  zigclaw queue worker [--once] [--max-jobs N] [--poll-ms N] [--config zigclaw.toml]
        \\  zigclaw queue status --request-id <id> [--include-payload] [--config zigclaw.toml]
        \\  zigclaw queue watch --request-id <id> [--include-payload] [--poll-ms N] [--timeout-ms N] [--json] [--config zigclaw.toml]
        \\  zigclaw queue cancel --request-id <id> [--config zigclaw.toml]
        \\  zigclaw queue metrics [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw queue enqueue-agent --message "nightly check" --request-id req_1
        \\  zigclaw queue watch --request-id req_1 --poll-ms 500
        \\  zigclaw queue metrics
        \\
        \\Related:
        \\  zigclaw gateway --help
        \\  zigclaw agent --help
    );
}

fn usageGit(io: std.Io) !void {
    try writeGroupHelp(io,
        \\git
        \\Usage:
        \\  zigclaw git init [--remote <url>] [--branch <name>] [--json] [--config zigclaw.toml]
        \\  zigclaw git status [--json] [--config zigclaw.toml]
        \\  zigclaw git sync [--message "..."] [--push] [--json] [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw git init --branch main
        \\  zigclaw git status --json
        \\  zigclaw git sync --message "sync memory updates" --push
        \\
        \\Related:
        \\  zigclaw task --help
        \\  zigclaw doctor --help
    );
}

fn usagePolicy(io: std.Io) !void {
    try writeGroupHelp(io,
        \\policy
        \\Usage:
        \\  zigclaw policy hash [--config zigclaw.toml] [--json]
        \\  zigclaw policy explain (--tool <name> | --mount <path> | --command "cmd") [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw policy hash --json
        \\  zigclaw policy explain --tool fs_read
        \\  zigclaw policy explain --command "wasmtime run --mapdir /workspace::/workspace plugin.wasm"
        \\
        \\Related:
        \\  zigclaw tools --help
        \\  zigclaw config --help
    );
}

fn usageAudit(io: std.Io) !void {
    try writeGroupHelp(io,
        \\audit
        \\Usage:
        \\  zigclaw audit report [--request-id <id>] [--from <ts>] [--to <ts>] [--format text|json] [--config zigclaw.toml]
        \\  zigclaw audit verify --request-id <id> [--format text|json] [--config zigclaw.toml]
        \\  zigclaw audit summary [--from <ts>] [--to <ts>] [--format text|json] [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw audit report --request-id req_1 --format text
        \\  zigclaw audit verify --request-id req_1 --format json
        \\  zigclaw audit summary --from 1700000000000 --format json
        \\
        \\Related:
        \\  zigclaw attest --help
        \\  zigclaw replay --help
    );
}

fn usageAttest(io: std.Io) !void {
    try writeGroupHelp(io,
        \\attest
        \\Usage:
        \\  zigclaw attest <request_id> [--config zigclaw.toml]
        \\  zigclaw attest verify --request-id <id> --event-index <n> [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw attest req_1
        \\  zigclaw attest verify --request-id req_1 --event-index 0
        \\
        \\Related:
        \\  zigclaw audit --help
        \\  zigclaw replay --help
    );
}

fn usageReplay(io: std.Io) !void {
    try writeGroupHelp(io,
        \\replay
        \\Usage:
        \\  zigclaw replay capture --request-id <id> [--config zigclaw.toml]
        \\  zigclaw replay run --capsule <path> [--config zigclaw.toml]
        \\  zigclaw replay diff --a <path1> --b <path2>
        \\
        \\Examples:
        \\  zigclaw replay capture --request-id req_1
        \\  zigclaw replay run --capsule ./.zigclaw/capsules/req_1.json
        \\  zigclaw replay diff --a cap_a.json --b cap_b.json
        \\
        \\Related:
        \\  zigclaw attest --help
        \\  zigclaw audit --help
    );
}

fn usageGateway(io: std.Io) !void {
    try writeGroupHelp(io,
        \\gateway
        \\Usage:
        \\  zigclaw gateway start [--bind 127.0.0.1] [--port 8787] [--config zigclaw.toml]
        \\
        \\Examples:
        \\  zigclaw gateway start
        \\  zigclaw gateway start --bind 0.0.0.0 --port 8787
        \\  zigclaw gateway start --config zigclaw.toml
        \\
        \\Related:
        \\  zigclaw queue --help
        \\  zigclaw doctor --help
    );
}

fn usageCompletion(io: std.Io) !void {
    try writeGroupHelp(io,
        \\completion
        \\Usage:
        \\  zigclaw completion zsh|bash|fish
        \\
        \\Examples:
        \\  zigclaw completion zsh > ~/.zfunc/_zigclaw
        \\  zigclaw completion bash > /etc/bash_completion.d/zigclaw
        \\  zigclaw completion fish > ~/.config/fish/completions/zigclaw.fish
        \\
        \\Related:
        \\  zigclaw --help
        \\  zigclaw doctor --help
    );
}

fn usageInit(io: std.Io) !void {
    try writeGroupHelp(io,
        \\init
        \\Usage:
        \\  zigclaw init [--full] [--json]
        \\  zigclaw init --quick [--full] [--json]
        \\  zigclaw init --guided
        \\
        \\Flags:
        \\  --full      Generate comprehensive config with all sections
        \\              (default generates a minimal ~15-line config)
        \\  --quick     Skip post-setup doctor check
        \\  --guided    Interactive setup wizard
        \\
        \\Examples:
        \\  zigclaw init
        \\  zigclaw init --full
        \\  zigclaw init --guided
        \\  zigclaw init --quick --json
        \\
        \\Related:
        \\  zigclaw setup --help
        \\  zigclaw doctor --help
    );
}

fn usageSetup(io: std.Io) !void {
    try writeGroupHelp(io,
        \\setup
        \\Usage:
        \\  zigclaw setup
        \\
        \\Examples:
        \\  zigclaw setup
        \\  zigclaw init --guided
        \\
        \\Related:
        \\  zigclaw init --help
        \\  zigclaw doctor --help
    );
}

fn writeGroupHelp(io: std.Io, text: []const u8) !void {
    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.writeAll(text);
    try w.interface.writeAll("\n");
    try w.flush();
}

fn printCliError(io: std.Io, argv: []const [:0]const u8, err: anyerror) !void {
    const cmd: []const u8 = if (argv.len >= 2) argv[1] else "";
    const as_json = hasFlag(argv, "--json");
    const hint = errorHint(cmd, err);
    const err_name = @errorName(err);

    var ebuf: [4096]u8 = undefined;
    var ew = std.Io.File.stderr().writer(io, &ebuf);

    if (as_json) {
        const payload = try jsonObj(std.heap.page_allocator, .{
            .ok = false,
            .command = cmd,
            .@"error" = err_name,
            .hint = hint,
        });
        defer std.heap.page_allocator.free(payload);
        try ew.interface.print("{s}\n", .{payload});
    } else {
        const term = @import("util/term.zig");
        const color = term.stderrSupportsColor();
        try term.writeStyled(&ew.interface, .red, "error:", color);
        try ew.interface.print(" {s}\n", .{err_name});
        if (hint) |h| {
            try term.writeStyled(&ew.interface, .yellow, "hint:", color);
            try ew.interface.print(" {s}\n", .{h});
        }
    }
    try ew.flush();
}

fn errorHint(cmd: []const u8, err: anyerror) ?[]const u8 {
    if (err == error.InvalidArgs) {
        if (std.mem.eql(u8, cmd, "agent")) return "agent arguments are invalid; `--json` cannot be combined with `--interactive`.";
        if (std.mem.eql(u8, cmd, "chat")) return "chat arguments are invalid; `--json` cannot be combined with interactive mode.";
        if (std.mem.eql(u8, cmd, "run")) return "run arguments are invalid; use `zigclaw run summary --request-id <id>`.";
        if (std.mem.eql(u8, cmd, "ops")) return "ops arguments are invalid; use `zigclaw ops summary|watch --help`.";
        if (std.mem.eql(u8, cmd, "vault")) return "vault arguments are invalid; run `zigclaw --help` for subcommand usage.";
        if (std.mem.eql(u8, cmd, "queue")) return "queue arguments are invalid; provide required --request-id or --message flags.";
        if (std.mem.eql(u8, cmd, "replay")) return "replay arguments are invalid; use --request-id/--capsule/--a/--b as required.";
        return "arguments are invalid; run `zigclaw --help` for command syntax.";
    }
    if (err == error.FileNotFound) {
        if (std.mem.eql(u8, cmd, "attest")) return "receipt file not found; run an agent request first and verify the request id.";
        if (std.mem.eql(u8, cmd, "replay")) return "capsule file not found; verify the --capsule path or capture a run first.";
        return "requested file/path was not found; verify the path and try again.";
    }
    if (err == error.TaskNotFound) return "task slug was not found; run `zigclaw task list` to find valid slugs.";
    if (err == error.DuplicateRequestId) return "request id already exists; use a unique --request-id.";
    if (err == error.ToolNotAllowed) return "tool denied by policy; run `zigclaw policy explain --tool <name>`.";
    if (err == error.ToolNetworkNotAllowed) return "tool requires network but active preset denies network; choose a different preset.";
    if (err == error.InvalidToolArgs) return "tool args do not match schema; run `zigclaw tools describe <tool>`.";
    if (err == error.UnregisteredTool) return "tool is not in compiled registry and tools.registry.strict=true; adjust presets or registry.";
    if (err == error.NetworkToolRequiresPresetNetwork) return "preset contains a network tool while allow_network=false.";
    if (err == error.DelegationPresetEscalation) return "delegation target preset exceeds parent permissions; make child preset a subset.";
    if (err == error.UnknownCapabilityPreset) return "agent references an unknown capability preset.";
    if (err == error.VaultPassphraseRequired) return "vault passphrase is required.";
    if (err == error.VaultKeyNotFound) return "vault key not found; set it with `zigclaw vault set <name>`.";
    if (err == error.ProviderApiKeyMissing) return "provider API key is missing; set providers.primary.api_key, providers.primary.api_key_vault, or export the configured api_key_env.";
    if (err == error.InvalidVaultFile or err == error.InvalidVaultData or err == error.DecryptionFailed) {
        return "vault decryption failed; verify passphrase and vault file path.";
    }
    if (err == error.ManifestFetchFailed) return "failed to fetch update manifest; check internet access or override --url.";
    if (err == error.InvalidManifest) return "update manifest format is invalid.";
    if (err == error.PlatformNotInManifest or err == error.UnsupportedPlatform) return "no update artifact for this platform.";
    if (err == error.DownloadFailed) return "failed to download update binary; check network and URL.";
    if (err == error.ChecksumMismatch) return "download checksum mismatch; retry update later.";
    if (err == error.ReplaceFailed) return "failed to replace zigclaw binary; check file permissions and install location.";
    if (err == error.GitNotInstalled) return "git is required but not available in PATH.";
    if (err == error.InvalidCapsule) return "replay capsule format is invalid.";
    if (err == error.EventIndexOutOfBounds) return "event index is out of range for this receipt.";
    return null;
}

/// When the config uses the stub provider and OPENAI_API_KEY is set in the
/// environment, auto-switch to openai_compat so that `zigclaw chat` works
/// with zero configuration.
fn applyEnvDefaults(validated: *config_mod.ValidatedConfig) void {
    if (validated.raw.provider_primary.kind != .stub) return;
    if (std.c.getenv("OPENAI_API_KEY")) |k| {
        if (std.mem.span(k).len > 0) {
            validated.raw.provider_primary.kind = .openai_compat;
            validated.raw.provider_primary.model = "gpt-4.1-mini";
            validated.raw.provider_primary.base_url = "https://api.openai.com/v1";
        }
    }
}

/// Apply ZIGCLAW_MODEL and ZIGCLAW_BASE_URL environment variable overrides.
/// These sit between config-file values and CLI flags in precedence.
fn applyEnvOverrides(validated: *config_mod.ValidatedConfig) void {
    if (std.c.getenv("ZIGCLAW_MODEL")) |m| {
        const s = std.mem.span(m);
        if (s.len > 0) validated.raw.provider_primary.model = s;
    }
    if (std.c.getenv("ZIGCLAW_BASE_URL")) |u| {
        const s = std.mem.span(u);
        if (s.len > 0) validated.raw.provider_primary.base_url = s;
    }
}

fn scaffoldProject(a: std.mem.Allocator, io: std.Io, as_json: bool, full: bool) !void {
    const dir = std.Io.Dir.cwd();
    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);

    // Check if zigclaw.toml already exists
    const exists = if (dir.statFile(io, "zigclaw.toml", .{})) |_| true else |_| false;
    if (exists) {
        if (as_json) {
            const out = try jsonObj(a, .{
                .ok = true,
                .created = false,
                .config_path = "zigclaw.toml",
                .reason = "already_exists",
            });
            defer a.free(out);
            try ow.interface.print("{s}\n", .{out});
        } else {
            try ow.interface.writeAll("zigclaw.toml already exists. Skipping.\n");
        }
        try ow.flush();
        return;
    }

    const minimal_config =
        \\# zigclaw.toml
        \\config_version = 1
        \\
        \\[providers.primary]
        \\kind = "openai_compat"
        \\model = "gpt-4.1-mini"
        \\base_url = "https://api.openai.com/v1"
        \\api_key_env = "OPENAI_API_KEY"
        \\
        \\[capabilities]
        \\active_preset = "dev"
        \\
        \\[capabilities.presets.dev]
        \\tools = ["echo", "fs_read", "fs_write", "shell_exec", "http_fetch"]
        \\allow_network = true
        \\allow_write_paths = ["./.zigclaw", "./tmp"]
        \\
    ;

    const full_config =
        \\# zigclaw.toml - generated by zigclaw init --full
        \\config_version = 1
        \\
        \\[capabilities]
        \\active_preset = "readonly"
        \\
        \\[capabilities.presets.readonly]
        \\tools = ["echo", "fs_read"]
        \\allow_network = false
        \\allow_write_paths = []
        \\
        \\[capabilities.presets.dev]
        \\tools = ["echo", "fs_read", "fs_write", "shell_exec", "http_fetch"]
        \\allow_network = true
        \\allow_write_paths = ["./.zigclaw", "./tmp"]
        \\
        \\[attestation]
        \\enabled = false
        \\
        \\[replay]
        \\enabled = false
        \\
        \\# Optional static multi-agent orchestration
        \\# [orchestration]
        \\# leader_agent = "planner"
        \\
        \\# [agents.planner]
        \\# capability_preset = "readonly"
        \\# delegate_to = ["writer"]
        \\# system_prompt = "Break work into steps and delegate."
        \\
        \\# [agents.writer]
        \\# capability_preset = "dev"
        \\# delegate_to = []
        \\# system_prompt = "Implement delegated tasks."
        \\
        \\[security]
        \\workspace_root = "."
        \\max_request_bytes = 262144
        \\
        \\[gateway]
        \\rate_limit_enabled = false
        \\rate_limit_store = "memory"
        \\rate_limit_window_ms = 1000
        \\rate_limit_max_requests = 60
        \\rate_limit_dir = "./.zigclaw/gateway_rate_limit"
        \\
        \\[providers.primary]
        \\kind = "openai_compat"
        \\model = "gpt-4.1-mini"
        \\temperature = 0.2
        \\base_url = "https://api.openai.com/v1"
        \\api_key_env = "OPENAI_API_KEY"
        \\
        \\[providers.fixtures]
        \\mode = "off"
        \\dir = "./.zigclaw/fixtures"
        \\capsule_path = ""
        \\
        \\[providers.reliable]
        \\retries = 2
        \\backoff_ms = 500
        \\
        \\[memory]
        \\backend = "markdown"
        \\root = "./.zigclaw/memory"
        \\
        \\[memory.primitives]
        \\enabled = true
        \\templates_dir = "./.zigclaw/memory/templates"
        \\strict_schema = true
        \\
        \\[tools]
        \\wasmtime_path = "wasmtime"
        \\plugin_dir = "./zig-out/bin"
        \\
        \\[tools.registry]
        \\strict = false
        \\
        \\[queue]
        \\dir = "./.zigclaw/queue"
        \\poll_ms = 1000
        \\max_retries = 2
        \\retry_backoff_ms = 500
        \\retry_jitter_pct = 20
        \\
        \\[automation]
        \\task_pickup_enabled = false
        \\default_owner = "zigclaw"
        \\pickup_statuses = ["open"]
        \\
        \\[persistence.git]
        \\enabled = false
        \\repo_dir = "."
        \\author_name = "zigclaw"
        \\author_email = "zigclaw@local"
        \\default_branch = "main"
        \\allow_paths = ["./.zigclaw/memory/tasks", "./.zigclaw/memory/projects", "./.zigclaw/memory/decisions", "./.zigclaw/memory/lessons", "./.zigclaw/memory/people", "./.zigclaw/memory/templates"]
        \\deny_paths = ["./.zigclaw/queue", "./.zigclaw/logs", "./.zigclaw/gateway.token", "./.zig-cache", "./zig-out"]
        \\push_default = false
        \\remote_name = "origin"
        \\
        \\[observability]
        \\enabled = true
        \\dir = "./.zigclaw/logs"
        \\max_file_bytes = 1048576
        \\max_files = 5
        \\
        \\[logging]
        \\enabled = true
        \\dir = "./.zigclaw"
        \\file = "decisions.jsonl"
        \\max_file_bytes = 1048576
        \\max_files = 5
        \\
    ;

    const config_data = if (full) full_config else minimal_config;
    try dir.writeFile(io, .{ .sub_path = "zigclaw.toml", .data = config_data });

    // Create directories
    dir.createDirPath(io, ".zigclaw/memory") catch {};
    dir.createDirPath(io, ".zigclaw/memory/tasks") catch {};
    dir.createDirPath(io, ".zigclaw/memory/projects") catch {};
    dir.createDirPath(io, ".zigclaw/memory/decisions") catch {};
    dir.createDirPath(io, ".zigclaw/memory/lessons") catch {};
    dir.createDirPath(io, ".zigclaw/memory/people") catch {};
    dir.createDirPath(io, ".zigclaw/memory/templates") catch {};
    dir.createDirPath(io, ".zigclaw/logs") catch {};
    dir.createDirPath(io, ".zigclaw/receipts") catch {};
    dir.createDirPath(io, ".zigclaw/capsules") catch {};
    dir.createDirPath(io, ".zigclaw/queue/incoming") catch {};
    dir.createDirPath(io, ".zigclaw/queue/processing") catch {};
    dir.createDirPath(io, ".zigclaw/queue/outgoing") catch {};
    dir.createDirPath(io, ".zigclaw/queue/canceled") catch {};
    dir.createDirPath(io, ".zigclaw/queue/cancel_requests") catch {};

    const default_tpl = @import("primitives/tasks.zig").default_task_template_md;
    const tpl_exists = if (dir.statFile(io, ".zigclaw/memory/templates/task.md", .{})) |_| true else |_| false;
    if (!tpl_exists) {
        dir.writeFile(io, .{ .sub_path = ".zigclaw/memory/templates/task.md", .data = default_tpl }) catch {};
    }

    if (as_json) {
        const out = try jsonObj(a, .{
            .ok = true,
            .created = true,
            .config_path = "zigclaw.toml",
            .workspace_dir = ".zigclaw",
            .full_config = full,
            .next_steps = .{
                "Set OPENAI_API_KEY (or set providers.primary.kind=\"stub\")",
                "zig build plugins",
                "zigclaw chat",
            },
        });
        defer a.free(out);
        try ow.interface.print("{s}\n", .{out});
    } else {
        try ow.interface.writeAll("Created zigclaw.toml and .zigclaw/ directories.\n");
        try ow.interface.writeAll("Next steps:\n");
        try ow.interface.writeAll("  1. Set OPENAI_API_KEY (or change providers.primary.kind to \"stub\")\n");
        try ow.interface.writeAll("  2. Build plugins: zig build plugins\n");
        try ow.interface.writeAll("  3. Run: zigclaw chat\n");
    }
    try ow.flush();
}

fn usage(io: std.Io) !void {
    const term = @import("util/term.zig");
    const color = term.stdoutSupportsColor();
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try term.writeStyled(&w.interface, .bold, "zigclaw", color);
    try w.interface.writeAll(" - local AI agent runtime\n\n");

    try term.writeStyled(&w.interface, .bold, "Getting Started:\n", color);
    try w.interface.writeAll(
        \\  init       Initialize workspace files
        \\  setup      Guided onboarding wizard
        \\  doctor     Run environment diagnostics
        \\
    );

    try w.interface.writeAll("\n");
    try term.writeStyled(&w.interface, .bold, "Agent:\n", color);
    try w.interface.writeAll(
        \\  chat       Interactive agent session (or one-shot with argument)
        \\  agent      Run agent (--message, --interactive, --agent)
        \\  tools      List, describe, and run tools
        \\  task       Manage tasks (add, list, done)
        \\
    );

    try w.interface.writeAll("\n");
    try term.writeStyled(&w.interface, .bold, "Operations:\n", color);
    try w.interface.writeAll(
        \\  ops        Dashboard and live watch
        \\  queue      Job queue (enqueue, worker, status, cancel)
        \\  gateway    Start HTTP gateway server
        \\
    );

    try w.interface.writeAll("\n");
    try term.writeStyled(&w.interface, .bold, "Configuration:\n", color);
    try w.interface.writeAll(
        \\  config     Validate configuration
        \\  vault      Manage encrypted secrets
        \\  policy     Hash and explain capability policies
        \\
    );

    try w.interface.writeAll(
        \\
        \\Use 'zigclaw <command> --help' for details.
        \\Use 'zigclaw --help-all' for all commands including audit, attest, replay, git, etc.
        \\
    );
    try w.flush();
}

fn usageAll(io: std.Io) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.writeAll(
        \\zigclaw - all commands
        \\
        \\Usage:
        \\  zigclaw version [--json]
        \\  zigclaw doctor [--config zigclaw.toml] [--json]
        \\  zigclaw setup
        \\  zigclaw update [--check] [--url <manifest-url>] [--json]
        \\  zigclaw chat ["message"] [--agent id] [--model m] [--preset p] [--config zigclaw.toml] [--json]
        \\  zigclaw agent --message "..." [--verbose] [--interactive] [--agent id] [--model m] [--preset p] [--config zigclaw.toml] [--json]
        \\  zigclaw run summary --request-id <id> [--config zigclaw.toml] [--json]
        \\  zigclaw ops summary [--format text|json] [--limit N] [--config zigclaw.toml]
        \\  zigclaw ops watch [--format text|json] [--limit N] [--poll-ms N] [--iterations N] [--config zigclaw.toml]
        \\  zigclaw vault set <name> [--vault <path>] [--json]
        \\  zigclaw vault get <name> [--vault <path>] [--json]
        \\  zigclaw vault list [--vault <path>] [--json]
        \\  zigclaw vault delete <name> [--vault <path>] [--json]
        \\  zigclaw init [--full] [--json]
        \\  zigclaw prompt dump --message "..." [--format json|text] [--out path] [--config zigclaw.toml]
        \\  zigclaw prompt diff --a file --b file [--json]
        \\  zigclaw tools list [--config zigclaw.toml]
        \\  zigclaw tools describe <tool> [--config zigclaw.toml]
        \\  zigclaw tools run <tool> --args '{}' [--config zigclaw.toml]
        \\  zigclaw task add "..." [--priority p] [--owner o] [--project p] [--tags "a,b"] [--status s] [--config zigclaw.toml]
        \\  zigclaw task list [--status s] [--owner o] [--project p] [--format text|json] [--config zigclaw.toml]
        \\  zigclaw task done <slug> [--reason "..."] [--config zigclaw.toml]
        \\  zigclaw primitive validate <slug|path> [--config zigclaw.toml]
        \\  zigclaw templates list [--config zigclaw.toml]
        \\  zigclaw templates show [task] [--config zigclaw.toml]
        \\  zigclaw templates validate [task] [--config zigclaw.toml]
        \\  zigclaw git init [--remote <url>] [--branch <name>] [--json] [--config zigclaw.toml]
        \\  zigclaw git status [--json] [--config zigclaw.toml]
        \\  zigclaw git sync [--message "..."] [--push] [--json] [--config zigclaw.toml]
        \\  zigclaw queue enqueue-agent --message "..." [--agent id] [--request-id id] [--config zigclaw.toml]
        \\  zigclaw queue worker [--once] [--max-jobs N] [--poll-ms N] [--config zigclaw.toml]
        \\  zigclaw queue status --request-id <id> [--include-payload] [--config zigclaw.toml]
        \\  zigclaw queue watch --request-id <id> [--include-payload] [--poll-ms N] [--timeout-ms N] [--json] [--config zigclaw.toml]
        \\  zigclaw queue cancel --request-id <id> [--config zigclaw.toml]
        \\  zigclaw queue metrics [--config zigclaw.toml]
        \\  zigclaw config validate [--config zigclaw.toml] [--format toml|text|json] [--json]
        \\  zigclaw policy hash [--config zigclaw.toml] [--json]
        \\  zigclaw policy explain (--tool <name> | --mount <path> | --command "cmd") [--config zigclaw.toml]
        \\  zigclaw audit report [--request-id <id>] [--from <ts>] [--to <ts>] [--format text|json] [--config zigclaw.toml]
        \\  zigclaw audit verify --request-id <id> [--format text|json] [--config zigclaw.toml]
        \\  zigclaw audit summary [--from <ts>] [--to <ts>] [--format text|json] [--config zigclaw.toml]
        \\  zigclaw attest <request_id> [--config zigclaw.toml]
        \\  zigclaw attest verify --request-id <id> --event-index <n> [--config zigclaw.toml]
        \\  zigclaw replay capture --request-id <id> [--config zigclaw.toml]
        \\  zigclaw replay run --capsule <path> [--config zigclaw.toml]
        \\  zigclaw replay diff --a <path1> --b <path2>
        \\  zigclaw gateway start [--bind 127.0.0.1] [--port 8787] [--config zigclaw.toml]
        \\  zigclaw completion zsh|bash|fish
        \\
    );
    try w.flush();
}
