const std = @import("std");
const App = @import("app.zig").App;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const check = gpa.deinit();
        if (check == .leak) std.log.err("memory leak detected", .{});
    }
    const a = gpa.allocator();

    const argv = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, argv);

    if (argv.len < 2) {
        try usage(std.io.getStdOut().writer());
        return;
    }

    const cmd = argv[1];
    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        try usage(std.io.getStdOut().writer());
        return;
    }

    var app = try App.init(a);
    defer app.deinit();

    if (std.mem.eql(u8, cmd, "config")) {
        const sub = if (argv.len >= 3) argv[2] else "help";
        if (std.mem.eql(u8, sub, "validate")) {
            const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
            const format = flagValue(argv, "--format") orelse "toml";

            const validated = try app.loadConfig(cfg_path);
            defer validated.deinit(a);

            if (validated.warnings.len > 0) {
                const ew = std.io.getStdErr().writer();
                for (validated.warnings) |wrn| {
                    try ew.print("warning: {s}: {s}\n", .{ wrn.key_path, wrn.message });
                }
            }

            if (std.mem.eql(u8, format, "toml")) {
                try validated.printNormalizedToml(a, std.io.getStdOut().writer());
            } else {
                try validated.print(std.io.getStdOut().writer());
            }
            return;
        }
        try usage(std.io.getStdOut().writer());
        return;
    }

    if (std.mem.eql(u8, cmd, "agent")) {
        const msg = flagValue(argv, "--message") orelse "hello";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";

        const validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        try app.runAgent(validated, msg);
        return;
    }

    if (std.mem.eql(u8, cmd, "prompt")) {
        const sub = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";

        const validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (std.mem.eql(u8, sub, "dump")) {
            const msg = flagValue(argv, "--message") orelse "";
            const format = flagValue(argv, "--format") orelse "json";
            const out_path = flagValue(argv, "--out");

            var b = try @import("agent/bundle.zig").build(a, validated, msg);
            defer b.deinit(a);

            const payload = if (std.mem.eql(u8, format, "text"))
                try @import("agent/bundle.zig").dumpTextAlloc(a, b)
            else
                try @import("agent/bundle.zig").dumpJsonAlloc(a, b);
            defer a.free(payload);

            if (out_path) |p| {
                var f = try std.fs.cwd().createFile(p, .{ .truncate = true });
                defer f.close();
                try f.writer().writeAll(payload);
                try f.writer().writeAll("\n");
            } else {
                try std.io.getStdOut().writer().print("{s}\n", .{payload});
            }
            return;
        }

        if (std.mem.eql(u8, sub, "diff")) {
            const a_path = flagValue(argv, "--a") orelse return error.InvalidArgs;
            const b_path = flagValue(argv, "--b") orelse return error.InvalidArgs;

            const left = try std.fs.cwd().readFileAlloc(a, a_path, 4 * 1024 * 1024);
            defer a.free(left);
            const right = try std.fs.cwd().readFileAlloc(a, b_path, 4 * 1024 * 1024);
            defer a.free(right);

            const d = try @import("util/diff.zig").diffTextAlloc(a, left, right);
            defer a.free(d);
            try std.io.getStdOut().writer().print("{s}", .{d});
            return;
        }

        try usage(std.io.getStdOut().writer());
        return;
    }

    if (std.mem.eql(u8, cmd, "tools")) {
        const sub = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        const validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (std.mem.eql(u8, sub, "list")) {
            const json = try @import("tools/manifest_runtime.zig").listToolsJsonAlloc(a, validated.raw.tools.plugin_dir);
            defer a.free(json);
            try std.io.getStdOut().writer().print("{s}\n", .{json});
            return;
        }

        if (std.mem.eql(u8, sub, "describe")) {
            if (argv.len < 4) return error.InvalidArgs;
            const tool = argv[3];
            const json = try @import("tools/manifest_runtime.zig").describeToolJsonAlloc(a, validated.raw.tools.plugin_dir, tool);
            defer a.free(json);
            try std.io.getStdOut().writer().print("{s}\n", .{json});
            return;
        }

        if (std.mem.eql(u8, sub, "run")) {
            if (argv.len < 4) return error.InvalidArgs;
            const tool = argv[3];
            const args_json = flagValue(argv, "--args") orelse "{}";

            const res = try app.runTool(validated, tool, args_json);
            defer res.deinit(a);

            const out = try res.toJsonAlloc(a);
            defer a.free(out);
            try std.io.getStdOut().writer().print("{s}\n", .{out});
            return;
        }

        try usage(std.io.getStdOut().writer());
        return;
    }

    if (std.mem.eql(u8, cmd, "policy")) {
        const sub = if (argv.len >= 3) argv[2] else "help";
        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        const validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        if (std.mem.eql(u8, sub, "hash")) {
            try std.io.getStdOut().writer().print("{s}\n", .{validated.policy.policyHash()});
            return;
        }

        if (std.mem.eql(u8, sub, "explain")) {
            const tool = flagValue(argv, "--tool") orelse return error.InvalidArgs;
            const json = try validated.policy.explainToolJsonAlloc(a, tool);
            defer a.free(json);
            try std.io.getStdOut().writer().print("{s}\n", .{json});
            return;
        }

        try usage(std.io.getStdOut().writer());
        return;
    }

    if (std.mem.eql(u8, cmd, "gateway")) {
        const sub = if (argv.len >= 3) argv[2] else "start";
        if (!std.mem.eql(u8, sub, "start")) {
            try usage(std.io.getStdOut().writer());
            return;
        }

        const bind = flagValue(argv, "--bind") orelse "127.0.0.1";
        const port_s = flagValue(argv, "--port") orelse "8787";
        const port = try std.fmt.parseInt(u16, port_s, 10);

        const cfg_path = flagValue(argv, "--config") orelse "zigclaw.toml";
        const validated = try app.loadConfig(cfg_path);
        defer validated.deinit(a);

        try @import("gateway/server.zig").start(a, &app, validated, bind, port);
        return;
    }

    try usage(std.io.getStdOut().writer());
}

fn flagValue(argv: []const []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 1 < argv.len) : (i += 1) {
        if (std.mem.eql(u8, argv[i], name)) return argv[i + 1];
    }
    return null;
}

fn usage(w: anytype) !void {
    try w.writeAll(
        \\zigclaw
        \\
        \\Usage:
        \\  zigclaw agent --message "..." [--config zigclaw.toml]
        \\  zigclaw prompt dump --message "..." [--format json|text] [--out path] [--config zigclaw.toml]
        \\  zigclaw prompt diff --a file --b file
        \\  zigclaw tools list [--config zigclaw.toml]
        \\  zigclaw tools describe <tool> [--config zigclaw.toml]
        \\  zigclaw tools run <tool> --args '{}' [--config zigclaw.toml]
        \\  zigclaw config validate [--config zigclaw.toml] [--format toml|text]
        \\  zigclaw policy hash [--config zigclaw.toml]
        \\  zigclaw policy explain --tool <name> [--config zigclaw.toml]
        \\  zigclaw gateway start [--bind 127.0.0.1] [--port 8787] [--config zigclaw.toml]
        \\
    );
}
