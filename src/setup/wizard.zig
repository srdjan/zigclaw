const std = @import("std");
const prompts = @import("prompts.zig");
const config = @import("../config.zig");

pub fn run(a: std.mem.Allocator, io: std.Io) !bool {
    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);

    try ow.interface.writeAll("\n--- zigclaw setup ---\n\n");
    try ow.flush();

    const dir = std.Io.Dir.cwd();

    // Check if config already exists
    const exists = if (dir.statFile(io, "zigclaw.toml", .{})) |_| true else |_| false;
    if (exists) {
        const overwrite = try prompts.readYesNo(io, "zigclaw.toml already exists. Overwrite?", false);
        if (!overwrite) {
            try ow.interface.writeAll("Aborted.\n");
            try ow.flush();
            return false;
        }
    }

    // --- Provider selection ---
    try ow.interface.writeAll("Provider configuration:\n");
    try ow.flush();
    const provider_idx = try prompts.readChoice(io, "Select LLM provider:", &.{
        "openai_compat (OpenAI, local LLMs, etc.)",
        "stub (no LLM, for testing)",
    });

    var cfg = config.Config{};

    if (provider_idx == 0) {
        cfg.provider_primary.kind = .openai_compat;

        var url_buf: [512]u8 = undefined;
        const url = try prompts.readLine(io, "Base URL [https://api.openai.com/v1]: ", &url_buf);
        if (url.len > 0) {
            cfg.provider_primary.base_url = try a.dupe(u8, url);
        }

        var model_buf: [256]u8 = undefined;
        const model = try prompts.readLine(io, "Model [gpt-4.1-mini]: ", &model_buf);
        if (model.len > 0) {
            cfg.provider_primary.model = try a.dupe(u8, model);
        }

        var env_buf: [256]u8 = undefined;
        const env_name = try prompts.readLine(io, "API key env var [OPENAI_API_KEY]: ", &env_buf);
        if (env_name.len > 0) {
            cfg.provider_primary.api_key_env = try a.dupe(u8, env_name);
        }
    } else {
        cfg.provider_primary.kind = .stub;
        cfg.provider_primary.model = try a.dupe(u8, "stub");
    }

    // --- Capability preset ---
    try ow.interface.writeAll("\n");
    try ow.flush();
    const preset_idx = try prompts.readChoice(io, "Select capability preset:", &.{
        "readonly (safe default: echo, fs_read)",
        "dev (full: echo, fs_read, fs_write, shell_exec, http_fetch)",
    });

    var preset_list = std.array_list.Managed(config.PresetConfig).init(a);

    if (preset_idx == 1) {
        cfg.capabilities.active_preset = try a.dupe(u8, "dev");
        try preset_list.append(.{
            .name = try a.dupe(u8, "readonly"),
            .tools = try dupeStrs(a, &.{ "echo", "fs_read" }),
            .allow_network = false,
            .allow_write_paths = try dupeStrs(a, &.{}),
        });
        try preset_list.append(.{
            .name = try a.dupe(u8, "dev"),
            .tools = try dupeStrs(a, &.{ "echo", "fs_read", "fs_write", "shell_exec", "http_fetch" }),
            .allow_network = true,
            .allow_write_paths = try dupeStrs(a, &.{ "./.zigclaw", "./tmp" }),
        });
    } else {
        cfg.capabilities.active_preset = try a.dupe(u8, "readonly");
        try preset_list.append(.{
            .name = try a.dupe(u8, "readonly"),
            .tools = try dupeStrs(a, &.{ "echo", "fs_read" }),
            .allow_network = false,
            .allow_write_paths = try dupeStrs(a, &.{}),
        });
        try preset_list.append(.{
            .name = try a.dupe(u8, "dev"),
            .tools = try dupeStrs(a, &.{ "echo", "fs_read", "fs_write", "shell_exec", "http_fetch" }),
            .allow_network = true,
            .allow_write_paths = try dupeStrs(a, &.{ "./.zigclaw", "./tmp" }),
        });
    }
    cfg.capabilities.presets = try preset_list.toOwnedSlice();

    // --- Multi-agent orchestration ---
    try ow.interface.writeAll("\n");
    try ow.flush();
    const want_orchestration = try prompts.readYesNo(io, "Enable multi-agent orchestration?", false);

    if (want_orchestration) {
        var agents_list = std.array_list.Managed(config.AgentProfileConfig).init(a);

        // Default: planner + writer
        try agents_list.append(.{
            .id = try a.dupe(u8, "planner"),
            .capability_preset = try a.dupe(u8, "readonly"),
            .delegate_to = try dupeStrs(a, &.{"writer"}),
            .system_prompt = try a.dupe(u8, "Break work into steps and delegate."),
        });
        try agents_list.append(.{
            .id = try a.dupe(u8, "writer"),
            .capability_preset = try a.dupe(u8, cfg.capabilities.active_preset),
            .delegate_to = try dupeStrs(a, &.{}),
            .system_prompt = try a.dupe(u8, "Implement delegated tasks."),
        });

        cfg.orchestration.leader_agent = try a.dupe(u8, "planner");

        // Multi-model: optionally use a different model for the worker agent
        try ow.interface.writeAll("\n");
        try ow.flush();
        const want_diff_model = try prompts.readYesNo(io, "Use a more capable model for the worker agent?", false);
        if (want_diff_model) {
            var capable_model_buf: [256]u8 = undefined;
            const capable_model = try prompts.readLine(io, "Worker model [gpt-4.1]: ", &capable_model_buf);
            const model_name = if (capable_model.len > 0) capable_model else "gpt-4.1";

            var named_list = std.array_list.Managed(config.NamedProviderConfig).init(a);
            try named_list.append(.{
                .name = try a.dupe(u8, "capable"),
                .kind = .openai_compat,
                .model = try a.dupe(u8, model_name),
                .api_key_env = if (cfg.provider_primary.api_key_env.ptr != (config.ProviderConfig{}).api_key_env.ptr)
                    try a.dupe(u8, cfg.provider_primary.api_key_env)
                else
                    @as([]const u8, ""),
            });
            cfg.provider_named = try named_list.toOwnedSlice();

            // Set the writer agent's provider to "capable"
            for (agents_list.items) |*ag| {
                if (std.mem.eql(u8, ag.id, "writer")) {
                    ag.provider = try a.dupe(u8, "capable");
                }
            }
        }

        cfg.orchestration.agents = try agents_list.toOwnedSlice();
    }

    // --- Validate ---
    try ow.interface.writeAll("\nValidating configuration...\n");
    try ow.flush();

    var validated = try config.loadAndValidateFromConfig(a, cfg);

    if (validated.warnings.len > 0) {
        var ebuf: [4096]u8 = undefined;
        var ew = std.Io.File.stderr().writer(io, &ebuf);
        for (validated.warnings) |wrn| {
            try ew.interface.print("  warning: {s}: {s}\n", .{ wrn.key_path, wrn.message });
        }
        try ew.flush();
    }

    // --- Serialize ---
    var toml_alloc: std.Io.Writer.Allocating = .init(a);
    defer toml_alloc.deinit();
    try validated.printNormalizedToml(a, &toml_alloc.writer);
    const toml_bytes = try toml_alloc.toOwnedSlice();
    defer a.free(toml_bytes);

    // --- Write file ---
    dir.writeFile(io, .{ .sub_path = "zigclaw.toml", .data = toml_bytes }) catch |e| {
        try ow.interface.print("Failed to write zigclaw.toml: {s}\n", .{@errorName(e)});
        try ow.flush();
        return false;
    };

    // --- Scaffold directories ---
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

    // Display result
    try ow.interface.writeAll("\nConfiguration written to zigclaw.toml\n");
    try ow.interface.print("Policy hash: {s}\n", .{validated.policy.policyHash()});
    try ow.interface.writeAll("\nNext steps:\n");
    if (cfg.provider_primary.kind == .openai_compat) {
        try ow.interface.print("  1. Set {s} environment variable\n", .{cfg.provider_primary.api_key_env});
    }
    for (cfg.provider_named) |np| {
        if (np.api_key_env.len > 0 and !std.mem.eql(u8, np.api_key_env, cfg.provider_primary.api_key_env)) {
            try ow.interface.print("     Also set {s} for provider \"{s}\"\n", .{ np.api_key_env, np.name });
        }
    }
    try ow.interface.writeAll("  2. Build plugins: zig build plugins\n");
    try ow.interface.writeAll("  3. Run: zigclaw agent --message \"hello\"\n");
    try ow.flush();

    validated.deinit(a);
    return true;
}

fn dupeStrs(a: std.mem.Allocator, items: []const []const u8) ![]const []const u8 {
    var out = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (out.items) |s| a.free(s);
        out.deinit();
    }
    for (items) |s| try out.append(try a.dupe(u8, s));
    return try out.toOwnedSlice();
}
