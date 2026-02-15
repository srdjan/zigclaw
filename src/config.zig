const std = @import("std");
const policy_mod = @import("policy.zig");

pub const ProviderKind = enum { stub, openai_compat };

pub const ProviderConfig = struct {
    kind: ProviderKind = .stub,
    model: []const u8 = "stub",
    temperature: f64 = 0.2,

    base_url: []const u8 = "https://api.openai.com/v1",
    api_key: []const u8 = "", // optional (can be empty); do not print in normalized config
    api_key_env: []const u8 = "OPENAI_API_KEY",
};

pub const FixturesMode = enum { off, record, replay };

pub const ProviderFixturesConfig = struct {
    mode: FixturesMode = .off,
    dir: []const u8 = "./.zigclaw/fixtures",
};

pub const ProviderReliableConfig = struct {
    retries: u32 = 0,
    backoff_ms: u32 = 250,
};

pub const MemoryBackend = enum { markdown, sqlite };

pub const MemoryConfig = struct {
    backend: MemoryBackend = .markdown,
    root: []const u8 = "./.zigclaw/memory",
};

pub const SecurityConfig = struct {
    workspace_root: []const u8 = ".",
    max_request_bytes: usize = 262144,
};

pub const ObservabilityConfig = struct {
    enabled: bool = true,
    dir: []const u8 = "./.zigclaw/logs",
    max_file_bytes: u64 = 1024 * 1024,
    max_files: u32 = 5,
};

pub const LoggingConfig = struct {
    enabled: bool = true,
    dir: []const u8 = "./.zigclaw",
    file: []const u8 = "decisions.jsonl",
    max_file_bytes: u64 = 1024 * 1024,
    max_files: u32 = 5,
};

pub const ToolsConfig = struct {
    wasmtime_path: []const u8 = "wasmtime",
    plugin_dir: []const u8 = "./zig-out/bin",
};

pub const QueueConfig = struct {
    dir: []const u8 = "./.zigclaw/queue",
    poll_ms: u32 = 1000,
    max_retries: u32 = 2,
    retry_backoff_ms: u32 = 500,
    retry_jitter_pct: u32 = 20,
};

pub const CapabilitiesConfig = struct {
    active_preset: []const u8 = "readonly",
    presets: []PresetConfig = &.{},
};

pub const PresetConfig = struct {
    name: []const u8,
    tools: []const []const u8,
    allow_network: bool,
    allow_write_paths: []const []const u8,
};

pub const AgentProfileConfig = struct {
    id: []const u8,
    capability_preset: []const u8,
    delegate_to: []const []const u8,
    system_prompt: []const u8,
};

pub const OrchestrationConfig = struct {
    leader_agent: []const u8 = "",
    agents: []AgentProfileConfig = &.{},
};

pub const Config = struct {
    config_version: u32 = 1,

    observability: ObservabilityConfig = .{},
    logging: LoggingConfig = .{},

    provider_primary: ProviderConfig = .{},
    provider_fixtures: ProviderFixturesConfig = .{},
    provider_reliable: ProviderReliableConfig = .{},

    memory: MemoryConfig = .{},
    security: SecurityConfig = .{},
    tools: ToolsConfig = .{},
    queue: QueueConfig = .{},
    capabilities: CapabilitiesConfig = .{},
    orchestration: OrchestrationConfig = .{},
};

pub const Warning = struct {
    key_path: []const u8,
    message: []const u8,
};

pub const ValidatedConfig = struct {
    raw: Config,
    policy: policy_mod.Policy,
    warnings: []Warning,

    pub fn deinit(self: *ValidatedConfig, a: std.mem.Allocator) void {
        self.policy.deinit(a);
        freeConfigStrings(a, &self.raw);
        freeWarnings(a, self.warnings);
    }

    pub fn print(self: ValidatedConfig, w: *std.Io.Writer) !void {
        const sys = self.raw;
        try w.print(
            \\ValidatedConfig:
            \\  config_version={d}
            \\  provider.primary.kind={s} model={s} temperature={d} base_url={s} api_key_env={s}
            \\  providers.fixtures.mode={s} dir={s}
            \\  providers.reliable.retries={d} backoff_ms={d}
            \\  memory.backend={s} root={s}
            \\  security.workspace_root={s} max_request_bytes={d}
            \\  tools.wasmtime_path={s} plugin_dir={s}
            \\  queue.dir={s} poll_ms={d} max_retries={d} retry_backoff_ms={d} retry_jitter_pct={d}
            \\  logging.enabled={s} dir={s} file={s} max_file_bytes={d} max_files={d}
            \\  capabilities.active_preset={s}
            \\  orchestration.leader_agent={s} agents={d}
            \\  policy.tools_allowed={d} presets={d}
            \\
        , .{
            sys.config_version,
            @tagName(sys.provider_primary.kind),
            sys.provider_primary.model,
            sys.provider_primary.temperature,
            sys.provider_primary.base_url,
            sys.provider_primary.api_key_env,
            @tagName(sys.provider_fixtures.mode),
            sys.provider_fixtures.dir,
            sys.provider_reliable.retries,
            sys.provider_reliable.backoff_ms,
            @tagName(sys.memory.backend),
            sys.memory.root,
            sys.security.workspace_root,
            sys.security.max_request_bytes,
            sys.tools.wasmtime_path,
            sys.tools.plugin_dir,
            sys.queue.dir,
            sys.queue.poll_ms,
            sys.queue.max_retries,
            sys.queue.retry_backoff_ms,
            sys.queue.retry_jitter_pct,
            if (sys.logging.enabled) "true" else "false",
            sys.logging.dir,
            sys.logging.file,
            sys.logging.max_file_bytes,
            sys.logging.max_files,
            sys.capabilities.active_preset,
            sys.orchestration.leader_agent,
            sys.orchestration.agents.len,
            self.policy.allowed_tools_count(),
            self.policy.presets_count(),
        });
    }

    pub fn printNormalizedToml(self: ValidatedConfig, a: std.mem.Allocator, w: *std.Io.Writer) !void {
        // Stable ordering output (minimal TOML). DO NOT print secrets.
        try w.print("config_version = {d}\n\n", .{self.raw.config_version});

        // [capabilities]
        try w.writeAll("[capabilities]\n");
        try w.writeAll("active_preset = ");
        try writeTomlString(w, self.raw.capabilities.active_preset);
        try w.writeAll("\n\n");

        // presets sorted by name
        const presets = self.raw.capabilities.presets;
        const idxs = try a.alloc(usize, presets.len);
        defer a.free(idxs);
        for (idxs, 0..) |*p, i| p.* = i;
        std.sort.block(usize, idxs, presets, struct {
            fn lessThan(presets_: []PresetConfig, ai: usize, bi: usize) bool {
                return std.mem.lessThan(u8, presets_[ai].name, presets_[bi].name);
            }
        }.lessThan);

        for (idxs) |i| {
            const p = presets[i];
            try w.print("[capabilities.presets.{s}]\n", .{p.name});
            try w.writeAll("tools = ");
            try writeTomlStringArray(w, p.tools);
            try w.writeAll("\n");
            try w.print("allow_network = {s}\n", .{if (p.allow_network) "true" else "false"});
            try w.writeAll("allow_write_paths = ");
            try writeTomlStringArray(w, p.allow_write_paths);
            try w.writeAll("\n\n");
        }

        // [orchestration] and [agents.<id>] are printed only when configured.
        if (self.raw.orchestration.leader_agent.len > 0 or self.raw.orchestration.agents.len > 0) {
            try w.writeAll("[orchestration]\n");
            try w.writeAll("leader_agent = ");
            try writeTomlString(w, self.raw.orchestration.leader_agent);
            try w.writeAll("\n\n");

            const agents = self.raw.orchestration.agents;
            const agent_idxs = try a.alloc(usize, agents.len);
            defer a.free(agent_idxs);
            for (agent_idxs, 0..) |*p, i| p.* = i;
            std.sort.block(usize, agent_idxs, agents, struct {
                fn lessThan(agents_: []AgentProfileConfig, ai: usize, bi: usize) bool {
                    return std.mem.lessThan(u8, agents_[ai].id, agents_[bi].id);
                }
            }.lessThan);

            for (agent_idxs) |i| {
                const ag = agents[i];
                try w.print("[agents.{s}]\n", .{ag.id});
                try w.writeAll("capability_preset = ");
                try writeTomlString(w, ag.capability_preset);
                try w.writeAll("\n");
                try w.writeAll("delegate_to = ");
                try writeTomlStringArray(w, ag.delegate_to);
                try w.writeAll("\n");
                if (ag.system_prompt.len > 0) {
                    try w.writeAll("system_prompt = ");
                    try writeTomlString(w, ag.system_prompt);
                    try w.writeAll("\n");
                }
                try w.writeAll("\n");
            }
        }

        // [observability]
        try w.writeAll("[observability]\n");
        try w.print("enabled = {s}\n", .{if (self.raw.observability.enabled) "true" else "false"});
        try w.writeAll("dir = ");
        try writeTomlString(w, self.raw.observability.dir);
        try w.writeAll("\n");
        try w.print("max_file_bytes = {d}\n", .{self.raw.observability.max_file_bytes});
        try w.print("max_files = {d}\n\n", .{self.raw.observability.max_files});

        // [logging]
        try w.writeAll("[logging]\n");
        try w.print("enabled = {s}\n", .{if (self.raw.logging.enabled) "true" else "false"});
        try w.writeAll("dir = ");
        try writeTomlString(w, self.raw.logging.dir);
        try w.writeAll("\n");
        try w.writeAll("file = ");
        try writeTomlString(w, self.raw.logging.file);
        try w.writeAll("\n");
        try w.print("max_file_bytes = {d}\n", .{self.raw.logging.max_file_bytes});
        try w.print("max_files = {d}\n\n", .{self.raw.logging.max_files});

        // [security]
        try w.writeAll("[security]\n");
        try w.writeAll("workspace_root = ");
        try writeTomlString(w, self.raw.security.workspace_root);
        try w.writeAll("\n");
        try w.print("max_request_bytes = {d}\n\n", .{self.raw.security.max_request_bytes});

        // [providers.primary]
        try w.writeAll("[providers.primary]\n");
        try w.writeAll("kind = ");
        try writeTomlString(w, @tagName(self.raw.provider_primary.kind));
        try w.writeAll("\n");
        try w.writeAll("model = ");
        try writeTomlString(w, self.raw.provider_primary.model);
        try w.writeAll("\n");
        try w.print("temperature = {d}\n", .{self.raw.provider_primary.temperature});
        try w.writeAll("base_url = ");
        try writeTomlString(w, self.raw.provider_primary.base_url);
        try w.writeAll("\n");
        try w.writeAll("api_key_env = ");
        try writeTomlString(w, self.raw.provider_primary.api_key_env);
        try w.writeAll("\n\n");

        // [providers.fixtures]
        try w.writeAll("[providers.fixtures]\n");
        try w.writeAll("mode = ");
        try writeTomlString(w, @tagName(self.raw.provider_fixtures.mode));
        try w.writeAll("\n");
        try w.writeAll("dir = ");
        try writeTomlString(w, self.raw.provider_fixtures.dir);
        try w.writeAll("\n\n");

        // [providers.reliable]
        try w.writeAll("[providers.reliable]\n");
        try w.print("retries = {d}\n", .{self.raw.provider_reliable.retries});
        try w.print("backoff_ms = {d}\n\n", .{self.raw.provider_reliable.backoff_ms});

        // [memory]
        try w.writeAll("[memory]\n");
        try w.writeAll("backend = ");
        try writeTomlString(w, @tagName(self.raw.memory.backend));
        try w.writeAll("\n");
        try w.writeAll("root = ");
        try writeTomlString(w, self.raw.memory.root);
        try w.writeAll("\n\n");

        // [tools]
        try w.writeAll("[tools]\n");
        try w.writeAll("wasmtime_path = ");
        try writeTomlString(w, self.raw.tools.wasmtime_path);
        try w.writeAll("\n");
        try w.writeAll("plugin_dir = ");
        try writeTomlString(w, self.raw.tools.plugin_dir);
        try w.writeAll("\n\n");

        // [queue]
        try w.writeAll("[queue]\n");
        try w.writeAll("dir = ");
        try writeTomlString(w, self.raw.queue.dir);
        try w.writeAll("\n");
        try w.print("poll_ms = {d}\n", .{self.raw.queue.poll_ms});
        try w.print("max_retries = {d}\n", .{self.raw.queue.max_retries});
        try w.print("retry_backoff_ms = {d}\n", .{self.raw.queue.retry_backoff_ms});
        try w.print("retry_jitter_pct = {d}\n", .{self.raw.queue.retry_jitter_pct});
    }
};

pub fn loadAndValidate(a: std.mem.Allocator, io: std.Io, path: []const u8) !ValidatedConfig {
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(1024 * 1024)) catch |e| {
        std.log.warn("config file not found ({s}); using defaults: {any}", .{ path, e });
        return validate(a, Config{}, &.{});
    };
    defer a.free(content);

    var parsed = try tomlParseKeyMap(a, content);
    defer parsed.deinit(a);

    var built = try buildTypedConfig(a, parsed);
    errdefer built.deinit(a);

    return validate(a, built.cfg, built.warnings);
}

fn validate(a: std.mem.Allocator, cfg: Config, warnings: []Warning) !ValidatedConfig {
    const pol = try policy_mod.Policy.fromConfig(a, cfg.capabilities, cfg.security.workspace_root);
    return .{ .raw = cfg, .policy = pol, .warnings = warnings };
}

// -----------------------------
// P1 parsing + typed config build
// -----------------------------

const Value = union(enum) {
    string: []const u8,
    boolean: bool,
    integer: i64,
    float: f64,
    array: []Value,

    pub fn deinit(self: *Value, a: std.mem.Allocator) void {
        switch (self.*) {
            .string => |s| a.free(s),
            .array => |arr| {
                for (arr) |*v| v.deinit(a);
                a.free(arr);
            },
            else => {},
        }
    }
};

const KeyMap = struct {
    map: std.StringHashMap(Value),

    pub fn init(a: std.mem.Allocator) KeyMap {
        return .{ .map = std.StringHashMap(Value).init(a) };
    }

    pub fn deinit(self: *KeyMap, a: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |e| {
            a.free(e.key_ptr.*);
            e.value_ptr.deinit(a);
        }
        self.map.deinit();
    }
};

const ParseResult = struct {
    keys: KeyMap,
    pub fn deinit(self: *ParseResult, a: std.mem.Allocator) void {
        self.keys.deinit(a);
    }
};

fn tomlParseKeyMap(a: std.mem.Allocator, input: []const u8) !ParseResult {
    var km = KeyMap.init(a);

    var table_prefix = std.array_list.Managed([]const u8).init(a);
    defer table_prefix.deinit();

    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |raw_line| {
        const line0 = std.mem.trim(u8, raw_line, " \t\r");
        if (line0.len == 0) continue;

        const hash = std.mem.indexOfScalar(u8, line0, '#');
        const line = std.mem.trim(u8, if (hash) |i| line0[0..i] else line0, " \t\r");
        if (line.len == 0) continue;

        if (line[0] == '[' and line[line.len - 1] == ']') {
            table_prefix.clearRetainingCapacity();
            const inside = std.mem.trim(u8, line[1 .. line.len - 1], " \t");
            var pit = std.mem.splitScalar(u8, inside, '.');
            while (pit.next()) |seg0| {
                const seg = std.mem.trim(u8, seg0, " \t");
                if (seg.len == 0) continue;
                try table_prefix.append(seg);
            }
            continue;
        }

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const k0 = std.mem.trim(u8, line[0..eq], " \t");
        const v0 = std.mem.trim(u8, line[eq + 1 ..], " \t");

        const key_path = try joinKeyPath(a, table_prefix.items, k0);
        errdefer a.free(key_path);

        var val = try parseValue(a, v0);
        errdefer val.deinit(a);

        if (km.map.contains(key_path)) {
            var old = km.map.get(key_path).?;
            old.deinit(a);
            _ = km.map.remove(key_path);
        }
        try km.map.put(key_path, val);
    }

    return .{ .keys = km };
}

fn joinKeyPath(a: std.mem.Allocator, prefix: []const []const u8, leaf: []const u8) ![]const u8 {
    var total: usize = leaf.len;
    for (prefix) |p| total += p.len + 1;
    var out = try a.alloc(u8, total);
    var i: usize = 0;
    for (prefix) |p| {
        std.mem.copyForwards(u8, out[i..][0..p.len], p);
        i += p.len;
        out[i] = '.';
        i += 1;
    }
    std.mem.copyForwards(u8, out[i..][0..leaf.len], leaf);
    return out;
}

const ParseError = error{ InvalidTomlValue, InvalidString, InvalidEscape, InvalidArray, InvalidFloat, InvalidInt, OutOfMemory };

fn parseValue(a: std.mem.Allocator, raw: []const u8) ParseError!Value {
    const t = std.mem.trim(u8, raw, " \t\r");
    if (t.len == 0) return error.InvalidTomlValue;

    if (t[0] == '"') return .{ .string = try parseBasicString(a, t) };
    if (std.mem.eql(u8, t, "true")) return .{ .boolean = true };
    if (std.mem.eql(u8, t, "false")) return .{ .boolean = false };
    if (t[0] == '[') return .{ .array = try parseArray(a, t) };

    if (std.mem.indexOfScalar(u8, t, '.') != null) {
        const f = std.fmt.parseFloat(f64, t) catch return error.InvalidFloat;
        return .{ .float = f };
    } else {
        const i = std.fmt.parseInt(i64, t, 10) catch return error.InvalidInt;
        return .{ .integer = i };
    }
}

fn parseBasicString(a: std.mem.Allocator, t: []const u8) ParseError![]const u8 {
    if (t.len < 2 or t[0] != '"' or t[t.len - 1] != '"') return error.InvalidString;
    const inner = t[1 .. t.len - 1];

    var out = std.array_list.Managed(u8).init(a);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < inner.len) : (i += 1) {
        const c = inner[i];
        if (c != '\\') {
            try out.append(c);
            continue;
        }
        if (i + 1 >= inner.len) return error.InvalidEscape;
        const n = inner[i + 1];
        i += 1;
        switch (n) {
            'n' => try out.append('\n'),
            'r' => try out.append('\r'),
            't' => try out.append('\t'),
            '\\' => try out.append('\\'),
            '"' => try out.append('"'),
            else => return error.InvalidEscape,
        }
    }

    return try out.toOwnedSlice();
}

fn parseArray(a: std.mem.Allocator, t: []const u8) ParseError![]Value {
    if (t.len < 2 or t[0] != '[' or t[t.len - 1] != ']') return error.InvalidArray;
    var inner = std.mem.trim(u8, t[1 .. t.len - 1], " \t\r");

    var items = std.array_list.Managed(Value).init(a);
    errdefer {
        for (items.items) |*v| v.deinit(a);
        items.deinit();
    }

    if (inner.len == 0) return try items.toOwnedSlice();

    var i: usize = 0;
    var start: usize = 0;
    var in_str = false;
    while (i <= inner.len) : (i += 1) {
        const at_end = i == inner.len;
        const c = if (!at_end) inner[i] else ',';
        if (c == '"' and (i == 0 or inner[i - 1] != '\\')) in_str = !in_str;
        const is_sep = (!in_str) and (c == ',');
        if (is_sep or at_end) {
            const part0 = std.mem.trim(u8, inner[start..i], " \t\r");
            if (part0.len > 0) {
                const v = try parseValue(a, part0);
                try items.append(v);
            }
            start = i + 1;
        }
    }

    return try items.toOwnedSlice();
}

// -----------------------------
// Typed Config builder + warnings
// -----------------------------

const BuildResult = struct {
    cfg: Config,
    warnings: []Warning,

    pub fn deinit(self: *BuildResult, a: std.mem.Allocator) void {
        freeConfigStrings(a, &self.cfg);
        freeWarnings(a, self.warnings);
    }
};

fn buildTypedConfig(a: std.mem.Allocator, parsed: ParseResult) !BuildResult {
    var cfg = Config{};
    errdefer freeConfigStrings(a, &cfg);

    var warns = std.array_list.Managed(Warning).init(a);
    errdefer {
        for (warns.items) |w| {
            a.free(w.key_path);
            a.free(w.message);
        }
        warns.deinit();
    }

    var preset_names = std.StringHashMap(void).init(a);
    defer preset_names.deinit();

    var agent_names = std.StringHashMap(void).init(a);
    defer agent_names.deinit();

    var it = parsed.keys.map.iterator();
    while (it.next()) |e| {
        const k = e.key_ptr.*;
        const v = e.value_ptr.*;

        if (std.mem.eql(u8, k, "config_version") or std.mem.eql(u8, k, "meta.config_version")) {
            cfg.config_version = try coerceU32(v);
            continue;
        }

        if (std.mem.eql(u8, k, "capabilities.active_preset")) {
            cfg.capabilities.active_preset = try coerceStringDup(a, v);
            continue;
        }

        if (std.mem.eql(u8, k, "orchestration.leader_agent")) {
            cfg.orchestration.leader_agent = try coerceStringDup(a, v);
            continue;
        }

        if (std.mem.eql(u8, k, "observability.enabled")) {
            cfg.observability.enabled = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "observability.dir")) {
            cfg.observability.dir = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "observability.max_file_bytes")) {
            cfg.observability.max_file_bytes = @as(u64, @intCast(try coerceUsize(v)));
            continue;
        }
        if (std.mem.eql(u8, k, "observability.max_files")) {
            cfg.observability.max_files = try coerceU32(v);
            continue;
        }
        if (std.mem.eql(u8, k, "logging.enabled")) {
            cfg.logging.enabled = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "logging.dir")) {
            cfg.logging.dir = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "logging.file")) {
            cfg.logging.file = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "logging.max_file_bytes")) {
            cfg.logging.max_file_bytes = @as(u64, @intCast(try coerceUsize(v)));
            continue;
        }
        if (std.mem.eql(u8, k, "logging.max_files")) {
            cfg.logging.max_files = try coerceU32(v);
            continue;
        }

        if (std.mem.eql(u8, k, "security.workspace_root")) {
            cfg.security.workspace_root = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "security.max_request_bytes")) {
            cfg.security.max_request_bytes = try coerceUsize(v);
            continue;
        }

        if (std.mem.eql(u8, k, "tools.wasmtime_path")) {
            cfg.tools.wasmtime_path = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "tools.plugin_dir")) {
            cfg.tools.plugin_dir = try coerceStringDup(a, v);
            continue;
        }

        if (std.mem.eql(u8, k, "queue.dir")) {
            cfg.queue.dir = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "queue.poll_ms")) {
            cfg.queue.poll_ms = try coerceU32(v);
            continue;
        }
        if (std.mem.eql(u8, k, "queue.max_retries")) {
            cfg.queue.max_retries = try coerceU32(v);
            continue;
        }
        if (std.mem.eql(u8, k, "queue.retry_backoff_ms")) {
            cfg.queue.retry_backoff_ms = try coerceU32(v);
            continue;
        }
        if (std.mem.eql(u8, k, "queue.retry_jitter_pct")) {
            cfg.queue.retry_jitter_pct = try coerceU32(v);
            continue;
        }

        if (std.mem.eql(u8, k, "providers.primary.kind")) {
            const s = try coerceString(v);
            if (std.mem.eql(u8, s, "stub")) cfg.provider_primary.kind = .stub else if (std.mem.eql(u8, s, "openai_compat")) cfg.provider_primary.kind = .openai_compat else {
                try warns.append(.{ .key_path = try a.dupe(u8, k), .message = try std.fmt.allocPrint(a, "unknown providers.primary.kind '{s}', using 'stub'", .{s}) });
                cfg.provider_primary.kind = .stub;
            }
            continue;
        }
        if (std.mem.eql(u8, k, "providers.primary.model")) {
            cfg.provider_primary.model = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "providers.primary.temperature")) {
            cfg.provider_primary.temperature = try coerceF64(v);
            continue;
        }
        if (std.mem.eql(u8, k, "providers.primary.base_url")) {
            cfg.provider_primary.base_url = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "providers.primary.api_key")) {
            // allow inline api_key (discouraged). Keep it in cfg but never print it.
            cfg.provider_primary.api_key = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "providers.primary.api_key_env")) {
            cfg.provider_primary.api_key_env = try coerceStringDup(a, v);
            continue;
        }

        if (std.mem.eql(u8, k, "providers.fixtures.mode")) {
            const s = try coerceString(v);
            if (std.mem.eql(u8, s, "off")) cfg.provider_fixtures.mode = .off else if (std.mem.eql(u8, s, "record")) cfg.provider_fixtures.mode = .record else if (std.mem.eql(u8, s, "replay")) cfg.provider_fixtures.mode = .replay else {
                try warns.append(.{ .key_path = try a.dupe(u8, k), .message = try std.fmt.allocPrint(a, "unknown providers.fixtures.mode '{s}', using 'off'", .{s}) });
                cfg.provider_fixtures.mode = .off;
            }
            continue;
        }
        if (std.mem.eql(u8, k, "providers.fixtures.dir")) {
            cfg.provider_fixtures.dir = try coerceStringDup(a, v);
            continue;
        }

        if (std.mem.eql(u8, k, "providers.reliable.retries")) {
            cfg.provider_reliable.retries = try coerceU32(v);
            continue;
        }
        if (std.mem.eql(u8, k, "providers.reliable.backoff_ms")) {
            cfg.provider_reliable.backoff_ms = try coerceU32(v);
            continue;
        }

        if (std.mem.eql(u8, k, "memory.backend")) {
            const s = try coerceString(v);
            if (std.mem.eql(u8, s, "markdown")) cfg.memory.backend = .markdown else if (std.mem.eql(u8, s, "sqlite")) cfg.memory.backend = .sqlite else {
                try warns.append(.{ .key_path = try a.dupe(u8, k), .message = try std.fmt.allocPrint(a, "unknown memory.backend '{s}', using 'markdown'", .{s}) });
                cfg.memory.backend = .markdown;
            }
            continue;
        }
        if (std.mem.eql(u8, k, "memory.root")) {
            cfg.memory.root = try coerceStringDup(a, v);
            continue;
        }

        if (std.mem.startsWith(u8, k, "capabilities.presets.")) {
            const rest = k["capabilities.presets.".len..];
            const dot = std.mem.indexOfScalar(u8, rest, '.') orelse {
                try unknownKeyWarn(a, &warns, k);
                continue;
            };
            const name = rest[0..dot];
            _ = try preset_names.put(name, {});
            continue;
        }

        if (std.mem.startsWith(u8, k, "agents.")) {
            const rest = k["agents.".len..];
            const dot = std.mem.indexOfScalar(u8, rest, '.') orelse {
                try unknownKeyWarn(a, &warns, k);
                continue;
            };
            const id = rest[0..dot];
            const field = rest[dot + 1 ..];
            if (std.mem.eql(u8, field, "capability_preset") or
                std.mem.eql(u8, field, "delegate_to") or
                std.mem.eql(u8, field, "system_prompt"))
            {
                _ = try agent_names.put(id, {});
                continue;
            }
            try unknownKeyWarn(a, &warns, k);
            continue;
        }

        try unknownKeyWarn(a, &warns, k);
    }

    if (cfg.config_version != 1) {
        try warns.append(.{ .key_path = try a.dupe(u8, "config_version"), .message = try std.fmt.allocPrint(a, "config_version={d} not recognized; behavior may be undefined", .{cfg.config_version}) });
    }

    if (cfg.queue.retry_jitter_pct > 100) {
        try warns.append(.{
            .key_path = try a.dupe(u8, "queue.retry_jitter_pct"),
            .message = try std.fmt.allocPrint(a, "retry_jitter_pct={d} out of range; clamping to 100", .{cfg.queue.retry_jitter_pct}),
        });
        cfg.queue.retry_jitter_pct = 100;
    }

    // Build presets
    var names = std.array_list.Managed([]const u8).init(a);
    defer names.deinit();
    {
        var itn = preset_names.keyIterator();
        while (itn.next()) |kp| try names.append(kp.*);
    }
    std.sort.block([]const u8, names.items, {}, struct {
        fn lt(_: void, a_: []const u8, b_: []const u8) bool {
            return std.mem.lessThan(u8, a_, b_);
        }
    }.lt);

    var presets = std.array_list.Managed(PresetConfig).init(a);
    errdefer {
        for (presets.items) |p| freePreset(a, p);
        presets.deinit();
    }

    for (names.items) |n| {
        const tools_key = try std.fmt.allocPrint(a, "capabilities.presets.{s}.tools", .{n});
        defer a.free(tools_key);
        const allow_net_key = try std.fmt.allocPrint(a, "capabilities.presets.{s}.allow_network", .{n});
        defer a.free(allow_net_key);
        const writes_key = try std.fmt.allocPrint(a, "capabilities.presets.{s}.allow_write_paths", .{n});
        defer a.free(writes_key);

        const tools_val = parsed.keys.map.get(tools_key);
        const allow_net_val = parsed.keys.map.get(allow_net_key);
        const writes_val = parsed.keys.map.get(writes_key);

        const tools = if (tools_val) |tv| try coerceStringArrayDup(a, tv) else try dupeStrs(a, &.{});
        const allow_network = if (allow_net_val) |av| try coerceBool(av) else false;
        const writes = if (writes_val) |wv| try coerceStringArrayDup(a, wv) else try dupeStrs(a, &.{});

        try presets.append(.{
            .name = try a.dupe(u8, n),
            .tools = tools,
            .allow_network = allow_network,
            .allow_write_paths = writes,
        });
    }

    if (presets.items.len == 0) {
        try presets.append(.{
            .name = try a.dupe(u8, "readonly"),
            .tools = try dupeStrs(a, &.{"echo"}),
            .allow_network = false,
            .allow_write_paths = try dupeStrs(a, &.{}),
        });
    }

    cfg.capabilities.presets = try presets.toOwnedSlice();

    // Build static agent profiles for multi-agent orchestration.
    var agent_ids = std.array_list.Managed([]const u8).init(a);
    defer agent_ids.deinit();
    {
        var ita = agent_names.keyIterator();
        while (ita.next()) |kp| try agent_ids.append(kp.*);
    }
    std.sort.block([]const u8, agent_ids.items, {}, struct {
        fn lt(_: void, a_: []const u8, b_: []const u8) bool {
            return std.mem.lessThan(u8, a_, b_);
        }
    }.lt);

    var agents = std.array_list.Managed(AgentProfileConfig).init(a);
    errdefer {
        for (agents.items) |ag| freeAgentProfile(a, ag);
        agents.deinit();
    }

    for (agent_ids.items) |id| {
        const preset_key = try std.fmt.allocPrint(a, "agents.{s}.capability_preset", .{id});
        defer a.free(preset_key);
        const delegate_to_key = try std.fmt.allocPrint(a, "agents.{s}.delegate_to", .{id});
        defer a.free(delegate_to_key);
        const prompt_key = try std.fmt.allocPrint(a, "agents.{s}.system_prompt", .{id});
        defer a.free(prompt_key);

        const preset_v = parsed.keys.map.get(preset_key);
        const delegate_v = parsed.keys.map.get(delegate_to_key);
        const prompt_v = parsed.keys.map.get(prompt_key);

        const capability_preset = if (preset_v) |pv| try coerceStringDup(a, pv) else try a.dupe(u8, cfg.capabilities.active_preset);
        const delegate_to = if (delegate_v) |dv| try coerceStringArrayDup(a, dv) else try dupeStrs(a, &.{});
        const system_prompt = if (prompt_v) |sv| try coerceStringDup(a, sv) else try a.dupe(u8, "");

        try agents.append(.{
            .id = try a.dupe(u8, id),
            .capability_preset = capability_preset,
            .delegate_to = delegate_to,
            .system_prompt = system_prompt,
        });
    }

    cfg.orchestration.agents = try agents.toOwnedSlice();

    if (cfg.orchestration.agents.len > 0 and cfg.orchestration.leader_agent.len == 0) {
        cfg.orchestration.leader_agent = try a.dupe(u8, cfg.orchestration.agents[0].id);
    }

    if (cfg.orchestration.agents.len > 0 and cfg.orchestration.leader_agent.len > 0) {
        var found = false;
        for (cfg.orchestration.agents) |ag| {
            if (std.mem.eql(u8, ag.id, cfg.orchestration.leader_agent)) {
                found = true;
                break;
            }
        }
        if (!found) {
            try warns.append(.{
                .key_path = try a.dupe(u8, "orchestration.leader_agent"),
                .message = try std.fmt.allocPrint(
                    a,
                    "leader '{s}' not found in [agents.*]; using '{s}'",
                    .{ cfg.orchestration.leader_agent, cfg.orchestration.agents[0].id },
                ),
            });
            a.free(cfg.orchestration.leader_agent);
            cfg.orchestration.leader_agent = try a.dupe(u8, cfg.orchestration.agents[0].id);
        }
    }

    if (cfg.orchestration.agents.len > 0) {
        for (cfg.orchestration.agents) |ag| {
            for (ag.delegate_to) |target| {
                var found = false;
                for (cfg.orchestration.agents) |candidate| {
                    if (std.mem.eql(u8, candidate.id, target)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    try warns.append(.{
                        .key_path = try std.fmt.allocPrint(a, "agents.{s}.delegate_to", .{ag.id}),
                        .message = try std.fmt.allocPrint(a, "unknown delegate target '{s}'", .{target}),
                    });
                }
            }
        }
    }

    return .{ .cfg = cfg, .warnings = try warns.toOwnedSlice() };
}

fn unknownKeyWarn(a: std.mem.Allocator, warns: *std.array_list.Managed(Warning), k: []const u8) !void {
    try warns.append(.{ .key_path = try a.dupe(u8, k), .message = try a.dupe(u8, "unknown key (ignored)") });
}

fn coerceString(v: Value) ![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => error.TypeMismatch,
    };
}
fn coerceStringDup(a: std.mem.Allocator, v: Value) ![]const u8 {
    const s = try coerceString(v);
    return try a.dupe(u8, s);
}
fn coerceBool(v: Value) !bool {
    return switch (v) {
        .boolean => |b| b,
        else => error.TypeMismatch,
    };
}
fn coerceU32(v: Value) !u32 {
    return switch (v) {
        .integer => |i| if (i >= 0 and i <= std.math.maxInt(u32)) @as(u32, @intCast(i)) else error.Range,
        else => error.TypeMismatch,
    };
}
fn coerceUsize(v: Value) !usize {
    return switch (v) {
        .integer => |i| if (i >= 0 and i <= std.math.maxInt(usize)) @as(usize, @intCast(i)) else error.Range,
        else => error.TypeMismatch,
    };
}
fn coerceF64(v: Value) !f64 {
    return switch (v) {
        .float => |f| f,
        .integer => |i| @as(f64, @floatFromInt(i)),
        else => error.TypeMismatch,
    };
}
fn coerceStringArrayDup(a: std.mem.Allocator, v: Value) ![]const []const u8 {
    return switch (v) {
        .array => |arr| {
            var out = std.array_list.Managed([]const u8).init(a);
            errdefer {
                for (out.items) |s| a.free(s);
                out.deinit();
            }
            for (arr) |item| {
                const s = try coerceString(item);
                try out.append(try a.dupe(u8, s));
            }
            return try out.toOwnedSlice();
        },
        else => error.TypeMismatch,
    };
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

// -----------------------------
// Small TOML formatting helpers
// -----------------------------

/// Free all heap-owned strings and presets in a Config.
/// Uses pointer comparison against defaults to skip static (non-heap) fields.
fn freeConfigStrings(a: std.mem.Allocator, cfg: *Config) void {
    const d = Config{};

    // Simple string fields - only free if pointer differs from compile-time default
    inline for (.{
        .{ &cfg.capabilities.active_preset, &d.capabilities.active_preset },
        .{ &cfg.observability.dir, &d.observability.dir },
        .{ &cfg.logging.dir, &d.logging.dir },
        .{ &cfg.logging.file, &d.logging.file },
        .{ &cfg.security.workspace_root, &d.security.workspace_root },
        .{ &cfg.tools.wasmtime_path, &d.tools.wasmtime_path },
        .{ &cfg.tools.plugin_dir, &d.tools.plugin_dir },
        .{ &cfg.queue.dir, &d.queue.dir },
        .{ &cfg.provider_primary.model, &d.provider_primary.model },
        .{ &cfg.provider_primary.base_url, &d.provider_primary.base_url },
        .{ &cfg.provider_primary.api_key, &d.provider_primary.api_key },
        .{ &cfg.provider_primary.api_key_env, &d.provider_primary.api_key_env },
        .{ &cfg.provider_fixtures.dir, &d.provider_fixtures.dir },
        .{ &cfg.memory.root, &d.memory.root },
        .{ &cfg.orchestration.leader_agent, &d.orchestration.leader_agent },
    }) |pair| {
        if (pair[0].*.ptr != pair[1].*.ptr) a.free(pair[0].*);
    }

    // Presets - only free if pointer differs from default empty slice
    if (cfg.capabilities.presets.ptr != d.capabilities.presets.ptr) {
        for (cfg.capabilities.presets) |p| freePreset(a, p);
        a.free(cfg.capabilities.presets);
    }

    if (cfg.orchestration.agents.ptr != d.orchestration.agents.ptr) {
        for (cfg.orchestration.agents) |ag| freeAgentProfile(a, ag);
        a.free(cfg.orchestration.agents);
    }
}

fn freePreset(a: std.mem.Allocator, p: PresetConfig) void {
    a.free(p.name);
    for (p.tools) |s| a.free(s);
    a.free(p.tools);
    for (p.allow_write_paths) |s| a.free(s);
    a.free(p.allow_write_paths);
}

fn freeAgentProfile(a: std.mem.Allocator, ag: AgentProfileConfig) void {
    a.free(ag.id);
    a.free(ag.capability_preset);
    for (ag.delegate_to) |s| a.free(s);
    a.free(ag.delegate_to);
    a.free(ag.system_prompt);
}

fn freeWarnings(a: std.mem.Allocator, warnings: []Warning) void {
    for (warnings) |w| {
        a.free(w.key_path);
        a.free(w.message);
    }
    if (warnings.len > 0) a.free(warnings);
}

fn writeTomlString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

fn writeTomlStringArray(w: *std.Io.Writer, items: []const []const u8) std.Io.Writer.Error!void {
    try w.writeByte('[');
    for (items, 0..) |s, i| {
        if (i != 0) try w.writeAll(", ");
        try writeTomlString(w, s);
    }
    try w.writeByte(']');
}
