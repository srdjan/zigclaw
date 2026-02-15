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
            const tool = flagValue(argv, "--tool") orelse return error.InvalidArgs;
            const json = try validated.policy.explainToolJsonAlloc(a, tool);
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
        \\
        \\[providers.reliable]
        \\retries = 2
        \\backoff_ms = 500
        \\
        \\[memory]
        \\backend = "markdown"
        \\root = "./.zigclaw/memory"
        \\
        \\[tools]
        \\wasmtime_path = "wasmtime"
        \\plugin_dir = "./zig-out/bin"
        \\
        \\[queue]
        \\dir = "./.zigclaw/queue"
        \\poll_ms = 1000
        \\max_retries = 2
        \\
        \\[observability]
        \\enabled = true
        \\dir = "./.zigclaw/logs"
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
    dir.createDirPath(io, ".zigclaw/logs") catch {};
    dir.createDirPath(io, ".zigclaw/queue/incoming") catch {};
    dir.createDirPath(io, ".zigclaw/queue/processing") catch {};
    dir.createDirPath(io, ".zigclaw/queue/outgoing") catch {};

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
        \\  zigclaw queue enqueue-agent --message "..." [--agent id] [--request-id id] [--config zigclaw.toml]
        \\  zigclaw queue worker [--once] [--max-jobs N] [--poll-ms N] [--config zigclaw.toml]
        \\  zigclaw config validate [--config zigclaw.toml] [--format toml|text]
        \\  zigclaw policy hash [--config zigclaw.toml]
        \\  zigclaw policy explain --tool <name> [--config zigclaw.toml]
        \\  zigclaw gateway start [--bind 127.0.0.1] [--port 8787] [--config zigclaw.toml]
        \\
    );
    try w.flush();
}
