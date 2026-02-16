const std = @import("std");
const App = @import("app.zig").App;

pub fn main(init: std.process.Init) !void {
    const a = init.gpa;
    const io = init.io;

    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    if (argv.len < 2) {
        try usage(io);
        return;
    }

    const cmd: []const u8 = argv[1];
    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        try usage(io);
        return;
    }

    var app = try App.init(a, io);
    defer app.deinit();

    if (std.mem.eql(u8, cmd, "config")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        if (std.mem.eql(u8, sub, "validate")) {
            const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
            const format = flagValue(argv, "--format") orelse "toml";

            var validated = try app.loadConfig(cfg_path);
            defer validated.deinit(a);

            if (validated.warnings.len > 0) {
                var buf: [4096]u8 = undefined;
                var fw = std.Io.File.stderr().writer(io, &buf);
                for (validated.warnings) |wrn| {
                    try fw.interface.print("warning: {s}: {s}\n", .{ wrn.key_path, wrn.message });
                }
                try fw.flush();
            }

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            if (std.mem.eql(u8, format, "toml")) {
                try validated.printNormalizedToml(a, &ow.interface);
            } else {
                try validated.print(&ow.interface);
            }
            try ow.flush();
            return;
        }
        try usage(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "agent")) {
        const msg = flagValue(argv, "--message") orelse "hello";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        const verbose = hasFlag(argv, "--verbose");
        const interactive = hasFlag(argv, "--interactive");
        const agent_id = flagValue(argv, "--agent");

        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        try app.runAgent(validated, msg, .{
            .verbose = verbose,
            .interactive = interactive,
            .agent_id = agent_id,
        });
        return;
    }

    if (std.mem.eql(u8, cmd, "init")) {
        try scaffoldProject(a, io);
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

            const left = try std.Io.Dir.cwd().readFileAlloc(io, a_path, a, std.Io.Limit.limited(4 * 1024 * 1024));
            defer a.free(left);
            const right = try std.Io.Dir.cwd().readFileAlloc(io, b_path, a, std.Io.Limit.limited(4 * 1024 * 1024));
            defer a.free(right);

            const d = try @import("util/diff.zig").diffTextAlloc(a, left, right);
            defer a.free(d);
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}", .{d});
            try ow.flush();
            return;
        }

        try usage(io);
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

        try usage(io);
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

        try usage(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "primitive")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        if (!std.mem.eql(u8, sub, "validate")) {
            try usage(io);
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

        try usage(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "queue")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (std.mem.eql(u8, sub, "enqueue-agent")) {
            const msg = flagValue(argv, "--message") orelse return error.InvalidArgs;
            const agent_id = flagValue(argv, "--agent");
            const request_id = flagValue(argv, "--request-id");

            const rid = try @import("queue/worker.zig").enqueueAgent(a, io, validated, msg, agent_id, request_id);
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

            try @import("queue/worker.zig").runWorker(a, io, validated, .{
                .once = once,
                .max_jobs = max_jobs,
                .poll_ms_override = poll_ms,
            });
            return;
        }

        if (std.mem.eql(u8, sub, "status")) {
            const rid = flagValue(argv, "--request-id") orelse return error.InvalidArgs;
            const include_payload = hasFlag(argv, "--include-payload");
            const out = try @import("queue/worker.zig").statusJsonAlloc(a, io, validated, rid, include_payload);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "cancel")) {
            const rid = flagValue(argv, "--request-id") orelse return error.InvalidArgs;
            const out = try @import("queue/worker.zig").cancelRequestJsonAlloc(a, io, validated, rid);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        if (std.mem.eql(u8, sub, "metrics")) {
            const out = try @import("queue/worker.zig").metricsJsonAlloc(a, io, validated);
            defer a.free(out);

            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{out});
            try ow.flush();
            return;
        }

        try usage(io);
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

        try usage(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "policy")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        var validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (std.mem.eql(u8, sub, "hash")) {
            var obuf: [4096]u8 = undefined;
            var ow = std.Io.File.stdout().writer(io, &obuf);
            try ow.interface.print("{s}\n", .{validated.policy.policyHash()});
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

        try usage(io);
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

        try usage(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "gateway")) {
        const sub: []const u8 = if (argv.len >= 3) argv[2] else "start";
        if (!std.mem.eql(u8, sub, "start")) {
            try usage(io);
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

    try usage(io);
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

fn jsonObj(a: std.mem.Allocator, value: anytype) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.write(value);
    return try aw.toOwnedSlice();
}

fn scaffoldProject(a: std.mem.Allocator, io: std.Io) !void {
    const dir = std.Io.Dir.cwd();
    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);

    // Check if zigclaw.toml already exists
    const exists = if (dir.statFile(io, "zigclaw.toml", .{})) |_| true else |_| false;
    if (exists) {
        try ow.interface.writeAll("zigclaw.toml already exists. Skipping.\n");
        try ow.flush();
        return;
    }

    const default_config =
        \\# zigclaw.toml - generated by zigclaw init
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

    dir.writeFile(io, .{ .sub_path = "zigclaw.toml", .data = default_config }) catch |e| {
        const msg = try std.fmt.allocPrint(a, "failed to write zigclaw.toml: {s}\n", .{@errorName(e)});
        defer a.free(msg);
        try ow.interface.writeAll(msg);
        try ow.flush();
        return;
    };

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

    try ow.interface.writeAll("Created zigclaw.toml and .zigclaw/ directories.\n");
    try ow.interface.writeAll("Next steps:\n");
    try ow.interface.writeAll("  1. Set OPENAI_API_KEY (or change providers.primary.kind to \"stub\")\n");
    try ow.interface.writeAll("  2. Build plugins: zig build plugins\n");
    try ow.interface.writeAll("  3. Run: zigclaw agent --message \"hello\"\n");
    try ow.flush();
}

fn usage(io: std.Io) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.writeAll(
        \\zigclaw
        \\
        \\Usage:
        \\  zigclaw init
        \\  zigclaw agent --message "..." [--verbose] [--interactive] [--agent id] [--config zigclaw.toml]
        \\  zigclaw prompt dump --message "..." [--format json|text] [--out path] [--config zigclaw.toml]
        \\  zigclaw prompt diff --a file --b file
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
        \\  zigclaw git sync [--message \"...\"] [--push] [--json] [--config zigclaw.toml]
        \\  zigclaw queue enqueue-agent --message "..." [--agent id] [--request-id id] [--config zigclaw.toml]
        \\  zigclaw queue worker [--once] [--max-jobs N] [--poll-ms N] [--config zigclaw.toml]
        \\  zigclaw queue status --request-id <id> [--include-payload] [--config zigclaw.toml]
        \\  zigclaw queue cancel --request-id <id> [--config zigclaw.toml]
        \\  zigclaw queue metrics [--config zigclaw.toml]
        \\  zigclaw config validate [--config zigclaw.toml] [--format toml|text]
        \\  zigclaw policy hash [--config zigclaw.toml]
        \\  zigclaw policy explain (--tool <name> | --mount <path> | --command "cmd") [--config zigclaw.toml]
        \\  zigclaw attest <request_id> [--config zigclaw.toml]
        \\  zigclaw attest verify --request-id <id> --event-index <n> [--config zigclaw.toml]
        \\  zigclaw replay capture --request-id <id> [--config zigclaw.toml]
        \\  zigclaw replay run --capsule <path> [--config zigclaw.toml]
        \\  zigclaw replay diff --a <path1> --b <path2>
        \\  zigclaw gateway start [--bind 127.0.0.1] [--port 8787] [--config zigclaw.toml]
        \\
    );
    try w.flush();
}
