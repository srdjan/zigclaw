const std = @import("std");
const policy_mod = @import("policy.zig");
const policy_algebra = @import("policy/algebra.zig");
const tools_registry = @import("tools/registry.zig");

pub const ProviderKind = enum { stub, openai_compat };

pub const ProviderConfig = struct {
    kind: ProviderKind = .stub,
    model: []const u8 = "stub",
    temperature: f64 = 0.2,

    base_url: []const u8 = "https://api.openai.com/v1",
    api_key: []const u8 = "", // optional (can be empty); do not print in normalized config
    api_key_vault: []const u8 = "", // vault key name for API key
    api_key_env: []const u8 = "OPENAI_API_KEY",
};

pub const NamedProviderConfig = struct {
    name: []const u8,
    kind: ProviderKind = .openai_compat,
    model: []const u8 = "",
    temperature: f64 = 0.2,
    base_url: []const u8 = "",
    api_key: []const u8 = "",
    api_key_vault: []const u8 = "",
    api_key_env: []const u8 = "",
};

pub const FixturesMode = enum { off, record, replay, capsule_replay };

pub const ProviderFixturesConfig = struct {
    mode: FixturesMode = .off,
    dir: []const u8 = "./.zigclaw/fixtures",
    capsule_path: []const u8 = "",
};

pub const ProviderReliableConfig = struct {
    retries: u32 = 0,
    backoff_ms: u32 = 250,
};

pub const MemoryBackend = enum { markdown, sqlite };

pub const MemoryPrimitivesConfig = struct {
    enabled: bool = true,
    templates_dir: []const u8 = "./.zigclaw/memory/templates",
    strict_schema: bool = true,
};

pub const MemoryConfig = struct {
    backend: MemoryBackend = .markdown,
    root: []const u8 = "./.zigclaw/memory",
    primitives: MemoryPrimitivesConfig = .{},
};

pub const SecurityConfig = struct {
    workspace_root: []const u8 = ".",
    max_request_bytes: usize = 262144,
};

pub const GatewayConfig = struct {
    rate_limit_enabled: bool = false,
    rate_limit_store: RateLimitStore = .memory,
    rate_limit_window_ms: u32 = 1000,
    rate_limit_max_requests: u32 = 60,
    rate_limit_dir: []const u8 = "./.zigclaw/gateway_rate_limit",
};

pub const RateLimitStore = enum { memory, file };

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

pub const AttestationConfig = struct {
    enabled: bool = false,
};

pub const ReplayConfig = struct {
    enabled: bool = false,
};

pub const ToolsConfig = struct {
    wasmtime_path: []const u8 = "wasmtime",
    plugin_dir: []const u8 = "./zig-out/bin",
    external_dir: []const u8 = "./ext-tools",
    registry: ToolsRegistryConfig = .{},
    filter: ToolsFilterConfig = .{},
};

pub const ToolsRegistryConfig = struct {
    strict: bool = false,
};

pub const ToolsFilterConfig = struct {
    allow_external: bool = false,
    external_allow_list: []const []const u8 = &.{},
};

pub const QueueConfig = struct {
    dir: []const u8 = "./.zigclaw/queue",
    poll_ms: u32 = 1000,
    max_retries: u32 = 2,
    retry_backoff_ms: u32 = 500,
    retry_jitter_pct: u32 = 20,
};

pub const AutomationConfig = struct {
    task_pickup_enabled: bool = false,
    default_owner: []const u8 = "zigclaw",
    pickup_statuses: []const []const u8 = &.{"open"},
};

pub const PersistenceGitConfig = struct {
    enabled: bool = false,
    repo_dir: []const u8 = ".",
    author_name: []const u8 = "zigclaw",
    author_email: []const u8 = "zigclaw@local",
    default_branch: []const u8 = "main",
    allow_paths: []const []const u8 = &.{
        "./.zigclaw/memory/tasks",
        "./.zigclaw/memory/projects",
        "./.zigclaw/memory/decisions",
        "./.zigclaw/memory/lessons",
        "./.zigclaw/memory/people",
        "./.zigclaw/memory/templates",
    },
    deny_paths: []const []const u8 = &.{
        "./.zigclaw/queue",
        "./.zigclaw/logs",
        "./.zigclaw/gateway.token",
        "./.zig-cache",
        "./zig-out",
    },
    push_default: bool = false,
    remote_name: []const u8 = "origin",
};

pub const PersistenceConfig = struct {
    git: PersistenceGitConfig = .{},
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
    provider: []const u8 = "",
    provider_model: []const u8 = "",
    provider_temperature: ?f64 = null,
    provider_base_url: []const u8 = "",
    provider_api_key_env: []const u8 = "",
};

pub const OrchestrationConfig = struct {
    leader_agent: []const u8 = "",
    agents: []AgentProfileConfig = &.{},
};

pub const Config = struct {
    config_version: u32 = 1,

    vault_path: []const u8 = "./.zigclaw/vault.enc",

    observability: ObservabilityConfig = .{},
    logging: LoggingConfig = .{},
    attestation: AttestationConfig = .{},
    replay: ReplayConfig = .{},

    provider_primary: ProviderConfig = .{},
    provider_named: []NamedProviderConfig = &.{},
    provider_fixtures: ProviderFixturesConfig = .{},
    provider_reliable: ProviderReliableConfig = .{},

    memory: MemoryConfig = .{},
    security: SecurityConfig = .{},
    gateway: GatewayConfig = .{},
    tools: ToolsConfig = .{},
    queue: QueueConfig = .{},
    automation: AutomationConfig = .{},
    persistence: PersistenceConfig = .{},
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
    comments: CommentMap,

    pub fn deinit(self: *ValidatedConfig, a: std.mem.Allocator) void {
        self.policy.deinit(a);
        freeConfigStrings(a, &self.raw);
        freeWarnings(a, self.warnings);
        self.comments.deinit(a);
    }

    pub fn print(self: ValidatedConfig, w: *std.Io.Writer) !void {
        const sys = self.raw;
        try w.print("ValidatedConfig:\n", .{});
        try w.print("  config_version={d}\n", .{sys.config_version});
        try w.print("  provider.primary.kind={s} model={s} temperature={d} base_url={s} api_key_env={s}\n", .{
            @tagName(sys.provider_primary.kind),
            sys.provider_primary.model,
            sys.provider_primary.temperature,
            sys.provider_primary.base_url,
            sys.provider_primary.api_key_env,
        });
        try w.print("  providers.fixtures.mode={s} dir={s} capsule_path={s}\n", .{
            @tagName(sys.provider_fixtures.mode),
            sys.provider_fixtures.dir,
            sys.provider_fixtures.capsule_path,
        });
        try w.print("  providers.reliable.retries={d} backoff_ms={d}\n", .{
            sys.provider_reliable.retries,
            sys.provider_reliable.backoff_ms,
        });
        try w.print("  memory.backend={s} root={s}\n", .{
            @tagName(sys.memory.backend),
            sys.memory.root,
        });
        try w.print("  memory.primitives.enabled={s} templates_dir={s} strict_schema={s}\n", .{
            if (sys.memory.primitives.enabled) "true" else "false",
            sys.memory.primitives.templates_dir,
            if (sys.memory.primitives.strict_schema) "true" else "false",
        });
        try w.print("  security.workspace_root={s} max_request_bytes={d}\n", .{
            sys.security.workspace_root,
            sys.security.max_request_bytes,
        });
        try w.print("  gateway.rate_limit_enabled={s} rate_limit_window_ms={d} rate_limit_max_requests={d}\n", .{
            if (sys.gateway.rate_limit_enabled) "true" else "false",
            sys.gateway.rate_limit_window_ms,
            sys.gateway.rate_limit_max_requests,
        });
        try w.print("  gateway.rate_limit_store={s} rate_limit_dir={s}\n", .{
            @tagName(sys.gateway.rate_limit_store),
            sys.gateway.rate_limit_dir,
        });
        try w.print("  tools.wasmtime_path={s} plugin_dir={s} external_dir={s} registry.strict={s}\n", .{
            sys.tools.wasmtime_path,
            sys.tools.plugin_dir,
            sys.tools.external_dir,
            if (sys.tools.registry.strict) "true" else "false",
        });
        try w.print("  tools.filter.allow_external={s} external_allow_list={d}\n", .{
            if (sys.tools.filter.allow_external) "true" else "false",
            sys.tools.filter.external_allow_list.len,
        });
        try w.print("  queue.dir={s} poll_ms={d} max_retries={d} retry_backoff_ms={d} retry_jitter_pct={d}\n", .{
            sys.queue.dir,
            sys.queue.poll_ms,
            sys.queue.max_retries,
            sys.queue.retry_backoff_ms,
            sys.queue.retry_jitter_pct,
        });
        try w.print("  automation.task_pickup_enabled={s} default_owner={s} pickup_statuses={d}\n", .{
            if (sys.automation.task_pickup_enabled) "true" else "false",
            sys.automation.default_owner,
            sys.automation.pickup_statuses.len,
        });
        try w.print("  persistence.git.enabled={s} repo_dir={s} push_default={s} allow_paths={d} deny_paths={d}\n", .{
            if (sys.persistence.git.enabled) "true" else "false",
            sys.persistence.git.repo_dir,
            if (sys.persistence.git.push_default) "true" else "false",
            sys.persistence.git.allow_paths.len,
            sys.persistence.git.deny_paths.len,
        });
        try w.print("  logging.enabled={s} dir={s} file={s} max_file_bytes={d} max_files={d}\n", .{
            if (sys.logging.enabled) "true" else "false",
            sys.logging.dir,
            sys.logging.file,
            sys.logging.max_file_bytes,
            sys.logging.max_files,
        });
        try w.print("  attestation.enabled={s} replay.enabled={s}\n", .{
            if (sys.attestation.enabled) "true" else "false",
            if (sys.replay.enabled) "true" else "false",
        });
        try w.print("  capabilities.active_preset={s}\n", .{sys.capabilities.active_preset});
        try w.print("  orchestration.leader_agent={s} agents={d}\n", .{
            sys.orchestration.leader_agent,
            sys.orchestration.agents.len,
        });
        try w.print("  providers.named.count={d}\n", .{sys.provider_named.len});
        try w.print("  policy.tools_allowed={d} presets={d}\n", .{
            self.policy.allowed_tools_count(),
            self.policy.presets_count(),
        });
    }

    pub fn printNormalizedToml(self: ValidatedConfig, a: std.mem.Allocator, w: *std.Io.Writer) !void {
        const cm = self.comments;
        // Stable ordering output (minimal TOML). DO NOT print secrets.
        try w.print("config_version = {d}", .{self.raw.config_version});
        try writeInlineComment(w, cm, "config_version");
        try w.writeAll("\n");
        if (self.raw.vault_path.len > 0) {
            try w.writeAll("vault_path = ");
            try writeTomlString(w, self.raw.vault_path);
            try writeInlineComment(w, cm, "vault_path");
            try w.writeAll("\n");
        }
        try w.writeAll("\n");

        // [capabilities]
        try writeSectionComment(w, cm, "capabilities");
        try w.writeAll("[capabilities]\n");
        try w.writeAll("active_preset = ");
        try writeTomlString(w, self.raw.capabilities.active_preset);
        try writeInlineComment(w, cm, "capabilities.active_preset");
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
            try writeSectionComment(w, cm, "orchestration");
            try w.writeAll("[orchestration]\n");
            try w.writeAll("leader_agent = ");
            try writeTomlString(w, self.raw.orchestration.leader_agent);
            try writeInlineComment(w, cm, "orchestration.leader_agent");
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
                if (ag.provider.len > 0) {
                    try w.writeAll("provider = ");
                    try writeTomlString(w, ag.provider);
                    try w.writeAll("\n");
                }
                if (ag.provider_model.len > 0) {
                    try w.writeAll("provider_model = ");
                    try writeTomlString(w, ag.provider_model);
                    try w.writeAll("\n");
                }
                if (ag.provider_temperature) |t| {
                    try w.print("provider_temperature = {d}\n", .{t});
                }
                if (ag.provider_base_url.len > 0) {
                    try w.writeAll("provider_base_url = ");
                    try writeTomlString(w, ag.provider_base_url);
                    try w.writeAll("\n");
                }
                if (ag.provider_api_key_env.len > 0) {
                    try w.writeAll("provider_api_key_env = ");
                    try writeTomlString(w, ag.provider_api_key_env);
                    try w.writeAll("\n");
                }
                try w.writeAll("\n");
            }
        }

        // [observability]
        try writeSectionComment(w, cm, "observability");
        try w.writeAll("[observability]\n");
        try w.print("enabled = {s}", .{if (self.raw.observability.enabled) "true" else "false"});
        try writeInlineComment(w, cm, "observability.enabled");
        try w.writeAll("\n");
        try w.writeAll("dir = ");
        try writeTomlString(w, self.raw.observability.dir);
        try writeInlineComment(w, cm, "observability.dir");
        try w.writeAll("\n");
        try w.print("max_file_bytes = {d}", .{self.raw.observability.max_file_bytes});
        try writeInlineComment(w, cm, "observability.max_file_bytes");
        try w.writeAll("\n");
        try w.print("max_files = {d}", .{self.raw.observability.max_files});
        try writeInlineComment(w, cm, "observability.max_files");
        try w.writeAll("\n\n");

        // [logging]
        try writeSectionComment(w, cm, "logging");
        try w.writeAll("[logging]\n");
        try w.print("enabled = {s}", .{if (self.raw.logging.enabled) "true" else "false"});
        try writeInlineComment(w, cm, "logging.enabled");
        try w.writeAll("\n");
        try w.writeAll("dir = ");
        try writeTomlString(w, self.raw.logging.dir);
        try writeInlineComment(w, cm, "logging.dir");
        try w.writeAll("\n");
        try w.writeAll("file = ");
        try writeTomlString(w, self.raw.logging.file);
        try writeInlineComment(w, cm, "logging.file");
        try w.writeAll("\n");
        try w.print("max_file_bytes = {d}", .{self.raw.logging.max_file_bytes});
        try writeInlineComment(w, cm, "logging.max_file_bytes");
        try w.writeAll("\n");
        try w.print("max_files = {d}", .{self.raw.logging.max_files});
        try writeInlineComment(w, cm, "logging.max_files");
        try w.writeAll("\n\n");

        // [attestation]
        try writeSectionComment(w, cm, "attestation");
        try w.writeAll("[attestation]\n");
        try w.print("enabled = {s}", .{if (self.raw.attestation.enabled) "true" else "false"});
        try writeInlineComment(w, cm, "attestation.enabled");
        try w.writeAll("\n\n");

        // [replay]
        try writeSectionComment(w, cm, "replay");
        try w.writeAll("[replay]\n");
        try w.print("enabled = {s}", .{if (self.raw.replay.enabled) "true" else "false"});
        try writeInlineComment(w, cm, "replay.enabled");
        try w.writeAll("\n\n");

        // [gateway]
        try writeSectionComment(w, cm, "gateway");
        try w.writeAll("[gateway]\n");
        try w.print("rate_limit_enabled = {s}", .{if (self.raw.gateway.rate_limit_enabled) "true" else "false"});
        try writeInlineComment(w, cm, "gateway.rate_limit_enabled");
        try w.writeAll("\n");
        try w.writeAll("rate_limit_store = ");
        try writeTomlString(w, @tagName(self.raw.gateway.rate_limit_store));
        try writeInlineComment(w, cm, "gateway.rate_limit_store");
        try w.writeAll("\n");
        try w.print("rate_limit_window_ms = {d}", .{self.raw.gateway.rate_limit_window_ms});
        try writeInlineComment(w, cm, "gateway.rate_limit_window_ms");
        try w.writeAll("\n");
        try w.print("rate_limit_max_requests = {d}", .{self.raw.gateway.rate_limit_max_requests});
        try writeInlineComment(w, cm, "gateway.rate_limit_max_requests");
        try w.writeAll("\n");
        try w.writeAll("rate_limit_dir = ");
        try writeTomlString(w, self.raw.gateway.rate_limit_dir);
        try writeInlineComment(w, cm, "gateway.rate_limit_dir");
        try w.writeAll("\n\n");

        // [security]
        try writeSectionComment(w, cm, "security");
        try w.writeAll("[security]\n");
        try w.writeAll("workspace_root = ");
        try writeTomlString(w, self.raw.security.workspace_root);
        try writeInlineComment(w, cm, "security.workspace_root");
        try w.writeAll("\n");
        try w.print("max_request_bytes = {d}", .{self.raw.security.max_request_bytes});
        try writeInlineComment(w, cm, "security.max_request_bytes");
        try w.writeAll("\n\n");

        // [providers.primary]
        try writeSectionComment(w, cm, "providers.primary");
        try w.writeAll("[providers.primary]\n");
        try w.writeAll("kind = ");
        try writeTomlString(w, @tagName(self.raw.provider_primary.kind));
        try writeInlineComment(w, cm, "providers.primary.kind");
        try w.writeAll("\n");
        try w.writeAll("model = ");
        try writeTomlString(w, self.raw.provider_primary.model);
        try writeInlineComment(w, cm, "providers.primary.model");
        try w.writeAll("\n");
        try w.print("temperature = {d}", .{self.raw.provider_primary.temperature});
        try writeInlineComment(w, cm, "providers.primary.temperature");
        try w.writeAll("\n");
        try w.writeAll("base_url = ");
        try writeTomlString(w, self.raw.provider_primary.base_url);
        try writeInlineComment(w, cm, "providers.primary.base_url");
        try w.writeAll("\n");
        if (self.raw.provider_primary.api_key_vault.len > 0) {
            try w.writeAll("api_key_vault = ");
            try writeTomlString(w, self.raw.provider_primary.api_key_vault);
            try writeInlineComment(w, cm, "providers.primary.api_key_vault");
            try w.writeAll("\n");
        }
        try w.writeAll("api_key_env = ");
        try writeTomlString(w, self.raw.provider_primary.api_key_env);
        try writeInlineComment(w, cm, "providers.primary.api_key_env");
        try w.writeAll("\n\n");

        // [providers.fixtures]
        try writeSectionComment(w, cm, "providers.fixtures");
        try w.writeAll("[providers.fixtures]\n");
        try w.writeAll("mode = ");
        try writeTomlString(w, @tagName(self.raw.provider_fixtures.mode));
        try writeInlineComment(w, cm, "providers.fixtures.mode");
        try w.writeAll("\n");
        try w.writeAll("dir = ");
        try writeTomlString(w, self.raw.provider_fixtures.dir);
        try writeInlineComment(w, cm, "providers.fixtures.dir");
        try w.writeAll("\n");
        try w.writeAll("capsule_path = ");
        try writeTomlString(w, self.raw.provider_fixtures.capsule_path);
        try writeInlineComment(w, cm, "providers.fixtures.capsule_path");
        try w.writeAll("\n\n");

        // [providers.reliable]
        try writeSectionComment(w, cm, "providers.reliable");
        try w.writeAll("[providers.reliable]\n");
        try w.print("retries = {d}", .{self.raw.provider_reliable.retries});
        try writeInlineComment(w, cm, "providers.reliable.retries");
        try w.writeAll("\n");
        try w.print("backoff_ms = {d}", .{self.raw.provider_reliable.backoff_ms});
        try writeInlineComment(w, cm, "providers.reliable.backoff_ms");
        try w.writeAll("\n\n");

        // [providers.<name>] - named providers sorted by name
        if (self.raw.provider_named.len > 0) {
            const np_idxs = try a.alloc(usize, self.raw.provider_named.len);
            defer a.free(np_idxs);
            for (np_idxs, 0..) |*p, i| p.* = i;
            const named = self.raw.provider_named;
            std.sort.block(usize, np_idxs, named, struct {
                fn lessThan(named_: []NamedProviderConfig, ai: usize, bi: usize) bool {
                    return std.mem.lessThan(u8, named_[ai].name, named_[bi].name);
                }
            }.lessThan);

            for (np_idxs) |i| {
                const np = named[i];
                try w.print("[providers.{s}]\n", .{np.name});
                try w.writeAll("kind = ");
                try writeTomlString(w, @tagName(np.kind));
                try w.writeAll("\n");
                if (np.model.len > 0) {
                    try w.writeAll("model = ");
                    try writeTomlString(w, np.model);
                    try w.writeAll("\n");
                }
                try w.print("temperature = {d}\n", .{np.temperature});
                if (np.base_url.len > 0) {
                    try w.writeAll("base_url = ");
                    try writeTomlString(w, np.base_url);
                    try w.writeAll("\n");
                }
                // Omit api_key (secret)
                if (np.api_key_vault.len > 0) {
                    try w.writeAll("api_key_vault = ");
                    try writeTomlString(w, np.api_key_vault);
                    try w.writeAll("\n");
                }
                if (np.api_key_env.len > 0) {
                    try w.writeAll("api_key_env = ");
                    try writeTomlString(w, np.api_key_env);
                    try w.writeAll("\n");
                }
                try w.writeAll("\n");
            }
        }

        // [memory]
        try writeSectionComment(w, cm, "memory");
        try w.writeAll("[memory]\n");
        try w.writeAll("backend = ");
        try writeTomlString(w, @tagName(self.raw.memory.backend));
        try writeInlineComment(w, cm, "memory.backend");
        try w.writeAll("\n");
        try w.writeAll("root = ");
        try writeTomlString(w, self.raw.memory.root);
        try writeInlineComment(w, cm, "memory.root");
        try w.writeAll("\n\n");

        // [memory.primitives]
        try writeSectionComment(w, cm, "memory.primitives");
        try w.writeAll("[memory.primitives]\n");
        try w.print("enabled = {s}", .{if (self.raw.memory.primitives.enabled) "true" else "false"});
        try writeInlineComment(w, cm, "memory.primitives.enabled");
        try w.writeAll("\n");
        try w.writeAll("templates_dir = ");
        try writeTomlString(w, self.raw.memory.primitives.templates_dir);
        try writeInlineComment(w, cm, "memory.primitives.templates_dir");
        try w.writeAll("\n");
        try w.print("strict_schema = {s}", .{if (self.raw.memory.primitives.strict_schema) "true" else "false"});
        try writeInlineComment(w, cm, "memory.primitives.strict_schema");
        try w.writeAll("\n\n");

        // [tools]
        try writeSectionComment(w, cm, "tools");
        try w.writeAll("[tools]\n");
        try w.writeAll("wasmtime_path = ");
        try writeTomlString(w, self.raw.tools.wasmtime_path);
        try writeInlineComment(w, cm, "tools.wasmtime_path");
        try w.writeAll("\n");
        try w.writeAll("plugin_dir = ");
        try writeTomlString(w, self.raw.tools.plugin_dir);
        try writeInlineComment(w, cm, "tools.plugin_dir");
        try w.writeAll("\n");
        try w.writeAll("external_dir = ");
        try writeTomlString(w, self.raw.tools.external_dir);
        try writeInlineComment(w, cm, "tools.external_dir");
        try w.writeAll("\n\n");

        // [tools.registry]
        try writeSectionComment(w, cm, "tools.registry");
        try w.writeAll("[tools.registry]\n");
        try w.print("strict = {s}", .{if (self.raw.tools.registry.strict) "true" else "false"});
        try writeInlineComment(w, cm, "tools.registry.strict");
        try w.writeAll("\n\n");

        // [tools.filter]
        try writeSectionComment(w, cm, "tools.filter");
        try w.writeAll("[tools.filter]\n");
        try w.print("allow_external = {s}", .{if (self.raw.tools.filter.allow_external) "true" else "false"});
        try writeInlineComment(w, cm, "tools.filter.allow_external");
        try w.writeAll("\n");
        try w.writeAll("external_allow_list = ");
        try writeTomlStringArray(w, self.raw.tools.filter.external_allow_list);
        try writeInlineComment(w, cm, "tools.filter.external_allow_list");
        try w.writeAll("\n\n");

        // [queue]
        try writeSectionComment(w, cm, "queue");
        try w.writeAll("[queue]\n");
        try w.writeAll("dir = ");
        try writeTomlString(w, self.raw.queue.dir);
        try writeInlineComment(w, cm, "queue.dir");
        try w.writeAll("\n");
        try w.print("poll_ms = {d}", .{self.raw.queue.poll_ms});
        try writeInlineComment(w, cm, "queue.poll_ms");
        try w.writeAll("\n");
        try w.print("max_retries = {d}", .{self.raw.queue.max_retries});
        try writeInlineComment(w, cm, "queue.max_retries");
        try w.writeAll("\n");
        try w.print("retry_backoff_ms = {d}", .{self.raw.queue.retry_backoff_ms});
        try writeInlineComment(w, cm, "queue.retry_backoff_ms");
        try w.writeAll("\n");
        try w.print("retry_jitter_pct = {d}", .{self.raw.queue.retry_jitter_pct});
        try writeInlineComment(w, cm, "queue.retry_jitter_pct");
        try w.writeAll("\n\n");

        // [automation]
        try writeSectionComment(w, cm, "automation");
        try w.writeAll("[automation]\n");
        try w.print("task_pickup_enabled = {s}", .{if (self.raw.automation.task_pickup_enabled) "true" else "false"});
        try writeInlineComment(w, cm, "automation.task_pickup_enabled");
        try w.writeAll("\n");
        try w.writeAll("default_owner = ");
        try writeTomlString(w, self.raw.automation.default_owner);
        try writeInlineComment(w, cm, "automation.default_owner");
        try w.writeAll("\n");
        try w.writeAll("pickup_statuses = ");
        try writeTomlStringArray(w, self.raw.automation.pickup_statuses);
        try writeInlineComment(w, cm, "automation.pickup_statuses");
        try w.writeAll("\n\n");

        // [persistence.git]
        try writeSectionComment(w, cm, "persistence.git");
        try w.writeAll("[persistence.git]\n");
        try w.print("enabled = {s}", .{if (self.raw.persistence.git.enabled) "true" else "false"});
        try writeInlineComment(w, cm, "persistence.git.enabled");
        try w.writeAll("\n");
        try w.writeAll("repo_dir = ");
        try writeTomlString(w, self.raw.persistence.git.repo_dir);
        try writeInlineComment(w, cm, "persistence.git.repo_dir");
        try w.writeAll("\n");
        try w.writeAll("author_name = ");
        try writeTomlString(w, self.raw.persistence.git.author_name);
        try writeInlineComment(w, cm, "persistence.git.author_name");
        try w.writeAll("\n");
        try w.writeAll("author_email = ");
        try writeTomlString(w, self.raw.persistence.git.author_email);
        try writeInlineComment(w, cm, "persistence.git.author_email");
        try w.writeAll("\n");
        try w.writeAll("default_branch = ");
        try writeTomlString(w, self.raw.persistence.git.default_branch);
        try writeInlineComment(w, cm, "persistence.git.default_branch");
        try w.writeAll("\n");
        try w.writeAll("allow_paths = ");
        try writeTomlStringArray(w, self.raw.persistence.git.allow_paths);
        try writeInlineComment(w, cm, "persistence.git.allow_paths");
        try w.writeAll("\n");
        try w.writeAll("deny_paths = ");
        try writeTomlStringArray(w, self.raw.persistence.git.deny_paths);
        try writeInlineComment(w, cm, "persistence.git.deny_paths");
        try w.writeAll("\n");
        try w.print("push_default = {s}", .{if (self.raw.persistence.git.push_default) "true" else "false"});
        try writeInlineComment(w, cm, "persistence.git.push_default");
        try w.writeAll("\n");
        try w.writeAll("remote_name = ");
        try writeTomlString(w, self.raw.persistence.git.remote_name);
        try writeInlineComment(w, cm, "persistence.git.remote_name");
        try w.writeAll("\n");
    }
};

pub fn loadAndValidate(a: std.mem.Allocator, io: std.Io, path: []const u8) !ValidatedConfig {
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(1024 * 1024)) catch |e| {
        std.log.warn("config file not found ({s}); using defaults: {any}", .{ path, e });
        return validate(a, Config{}, &.{}, CommentMap.init(a));
    };
    defer a.free(content);

    var parsed = try tomlParseKeyMap(a, content);
    // Transfer comment ownership to ValidatedConfig; only free keys on deinit.
    defer parsed.keys.deinit(a);

    var built = try buildTypedConfig(a, parsed);
    errdefer built.deinit(a);

    return validate(a, built.cfg, built.warnings, parsed.comments);
}

pub fn loadAndValidateFromConfig(a: std.mem.Allocator, cfg: Config) !ValidatedConfig {
    return validate(a, cfg, &.{}, CommentMap.init(a));
}

fn validate(a: std.mem.Allocator, cfg: Config, warnings: []Warning, comments: CommentMap) !ValidatedConfig {
    const pol = try policy_mod.Policy.fromConfig(a, cfg.capabilities, cfg.security.workspace_root);
    return .{ .raw = cfg, .policy = pol, .warnings = warnings, .comments = comments };
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

/// Stores comments from the original TOML file, separated into inline
/// comments ("key = val # comment") and block comments (standalone # lines
/// preceding a key or section header).
pub const CommentMap = struct {
    /// Inline comments keyed by TOML key path (e.g. "providers.primary.kind").
    inline_comments: std.StringHashMap([]const u8),
    /// Block comments keyed by TOML key path or "@section.path" for sections.
    block_comments: std.StringHashMap([]const u8),

    pub fn init(a: std.mem.Allocator) CommentMap {
        return .{
            .inline_comments = std.StringHashMap([]const u8).init(a),
            .block_comments = std.StringHashMap([]const u8).init(a),
        };
    }

    pub fn deinit(self: *CommentMap, a: std.mem.Allocator) void {
        var it = self.inline_comments.iterator();
        while (it.next()) |e| {
            a.free(e.key_ptr.*);
            a.free(e.value_ptr.*);
        }
        self.inline_comments.deinit();
        var it2 = self.block_comments.iterator();
        while (it2.next()) |e| {
            a.free(e.key_ptr.*);
            a.free(e.value_ptr.*);
        }
        self.block_comments.deinit();
    }

    pub fn getInline(self: CommentMap, key: []const u8) ?[]const u8 {
        return self.inline_comments.get(key);
    }

    pub fn getBlock(self: CommentMap, key: []const u8) ?[]const u8 {
        return self.block_comments.get(key);
    }
};

const ParseResult = struct {
    keys: KeyMap,
    comments: CommentMap,
    pub fn deinit(self: *ParseResult, a: std.mem.Allocator) void {
        self.keys.deinit(a);
        self.comments.deinit(a);
    }
};

fn tomlParseKeyMap(a: std.mem.Allocator, input: []const u8) !ParseResult {
    var km = KeyMap.init(a);
    var cm = CommentMap.init(a);

    var table_prefix = std.array_list.Managed([]const u8).init(a);
    defer table_prefix.deinit();

    // Accumulator for standalone comment lines preceding a key or section.
    var pending_block_comment = std.array_list.Managed(u8).init(a);
    defer pending_block_comment.deinit();

    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |raw_line| {
        const line0 = std.mem.trim(u8, raw_line, " \t\r");
        if (line0.len == 0) {
            // Blank line resets the block comment accumulator.
            pending_block_comment.clearRetainingCapacity();
            continue;
        }

        // Extract inline comment (the part after #).
        const hash = std.mem.indexOfScalar(u8, line0, '#');
        const line = std.mem.trim(u8, if (hash) |i| line0[0..i] else line0, " \t\r");

        // Full-line comment: accumulate for the next key/section.
        if (line.len == 0 and hash != null) {
            const comment_text = std.mem.trim(u8, line0[hash.? + 1 ..], " \t");
            if (pending_block_comment.items.len > 0) {
                try pending_block_comment.append('\n');
            }
            try pending_block_comment.appendSlice(comment_text);
            continue;
        }
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
            // Store block comment for the section header itself.
            if (pending_block_comment.items.len > 0) {
                const section_key = try joinSectionKey(a, table_prefix.items);
                try cm.block_comments.put(section_key, try a.dupe(u8, pending_block_comment.items));
                pending_block_comment.clearRetainingCapacity();
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

        // Store inline comment (text after # on this key=value line).
        const inline_comment = if (hash) |h| std.mem.trim(u8, line0[h + 1 ..], " \t") else "";
        if (inline_comment.len > 0) {
            try cm.inline_comments.put(
                try a.dupe(u8, key_path),
                try a.dupe(u8, inline_comment),
            );
        }

        // Store block comment (accumulated standalone # lines before this key).
        if (pending_block_comment.items.len > 0) {
            try cm.block_comments.put(
                try a.dupe(u8, key_path),
                try a.dupe(u8, pending_block_comment.items),
            );
            pending_block_comment.clearRetainingCapacity();
        }
    }

    return .{ .keys = km, .comments = cm };
}

fn joinSectionKey(a: std.mem.Allocator, parts: []const []const u8) ![]const u8 {
    if (parts.len == 0) return try a.dupe(u8, "");
    var total: usize = 0;
    for (parts, 0..) |p, i| {
        total += p.len;
        if (i > 0) total += 1;
    }
    // Prefix with @ to distinguish section comments from key comments.
    var out = try a.alloc(u8, total + 1);
    out[0] = '@';
    var pos: usize = 1;
    for (parts, 0..) |p, i| {
        if (i > 0) {
            out[pos] = '.';
            pos += 1;
        }
        std.mem.copyForwards(u8, out[pos..][0..p.len], p);
        pos += p.len;
    }
    return out;
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

    var named_provider_names = std.StringHashMap(void).init(a);
    defer named_provider_names.deinit();

    var it = parsed.keys.map.iterator();
    while (it.next()) |e| {
        const k = e.key_ptr.*;
        const v = e.value_ptr.*;

        if (std.mem.eql(u8, k, "config_version") or std.mem.eql(u8, k, "meta.config_version")) {
            cfg.config_version = try coerceU32(v);
            continue;
        }

        if (std.mem.eql(u8, k, "vault_path")) {
            cfg.vault_path = try coerceStringDup(a, v);
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
        if (std.mem.eql(u8, k, "attestation.enabled")) {
            cfg.attestation.enabled = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "replay.enabled")) {
            cfg.replay.enabled = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "gateway.rate_limit_enabled")) {
            cfg.gateway.rate_limit_enabled = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "gateway.rate_limit_window_ms")) {
            cfg.gateway.rate_limit_window_ms = try coerceU32(v);
            continue;
        }
        if (std.mem.eql(u8, k, "gateway.rate_limit_max_requests")) {
            cfg.gateway.rate_limit_max_requests = try coerceU32(v);
            continue;
        }
        if (std.mem.eql(u8, k, "gateway.rate_limit_store")) {
            const s = try coerceString(v);
            if (std.mem.eql(u8, s, "memory")) cfg.gateway.rate_limit_store = .memory else if (std.mem.eql(u8, s, "file")) cfg.gateway.rate_limit_store = .file else {
                try warns.append(.{ .key_path = try a.dupe(u8, k), .message = try std.fmt.allocPrint(a, "unknown gateway.rate_limit_store '{s}', using 'memory'", .{s}) });
                cfg.gateway.rate_limit_store = .memory;
            }
            continue;
        }
        if (std.mem.eql(u8, k, "gateway.rate_limit_dir")) {
            cfg.gateway.rate_limit_dir = try coerceStringDup(a, v);
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
        if (std.mem.eql(u8, k, "tools.registry.strict")) {
            cfg.tools.registry.strict = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "tools.external_dir")) {
            cfg.tools.external_dir = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "tools.filter.allow_external")) {
            cfg.tools.filter.allow_external = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "tools.filter.external_allow_list")) {
            cfg.tools.filter.external_allow_list = try coerceStringArrayDup(a, v);
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
        if (std.mem.eql(u8, k, "providers.primary.api_key_vault")) {
            cfg.provider_primary.api_key_vault = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "providers.primary.api_key_env")) {
            cfg.provider_primary.api_key_env = try coerceStringDup(a, v);
            continue;
        }

        if (std.mem.eql(u8, k, "providers.fixtures.mode")) {
            const s = try coerceString(v);
            if (std.mem.eql(u8, s, "off")) cfg.provider_fixtures.mode = .off else if (std.mem.eql(u8, s, "record")) cfg.provider_fixtures.mode = .record else if (std.mem.eql(u8, s, "replay")) cfg.provider_fixtures.mode = .replay else if (std.mem.eql(u8, s, "capsule_replay")) cfg.provider_fixtures.mode = .capsule_replay else {
                try warns.append(.{ .key_path = try a.dupe(u8, k), .message = try std.fmt.allocPrint(a, "unknown providers.fixtures.mode '{s}', using 'off'", .{s}) });
                cfg.provider_fixtures.mode = .off;
            }
            continue;
        }
        if (std.mem.eql(u8, k, "providers.fixtures.dir")) {
            cfg.provider_fixtures.dir = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "providers.fixtures.capsule_path")) {
            cfg.provider_fixtures.capsule_path = try coerceStringDup(a, v);
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

        // Named providers: providers.X.Y where X is not primary/fixtures/reliable
        if (std.mem.startsWith(u8, k, "providers.")) {
            const rest = k["providers.".len..];
            if (!std.mem.startsWith(u8, rest, "primary.") and
                !std.mem.startsWith(u8, rest, "fixtures.") and
                !std.mem.startsWith(u8, rest, "reliable."))
            {
                const dot = std.mem.indexOfScalar(u8, rest, '.') orelse {
                    try unknownKeyWarn(a, &warns, k);
                    continue;
                };
                const prov_name = rest[0..dot];
                _ = try named_provider_names.put(prov_name, {});
                continue;
            }
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
        if (std.mem.eql(u8, k, "memory.primitives.enabled")) {
            cfg.memory.primitives.enabled = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "memory.primitives.templates_dir")) {
            cfg.memory.primitives.templates_dir = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "memory.primitives.strict_schema")) {
            cfg.memory.primitives.strict_schema = try coerceBool(v);
            continue;
        }

        if (std.mem.eql(u8, k, "automation.task_pickup_enabled")) {
            cfg.automation.task_pickup_enabled = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "automation.default_owner")) {
            cfg.automation.default_owner = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "automation.pickup_statuses")) {
            cfg.automation.pickup_statuses = try coerceStringArrayDup(a, v);
            continue;
        }

        if (std.mem.eql(u8, k, "persistence.git.enabled")) {
            cfg.persistence.git.enabled = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "persistence.git.repo_dir")) {
            cfg.persistence.git.repo_dir = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "persistence.git.author_name")) {
            cfg.persistence.git.author_name = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "persistence.git.author_email")) {
            cfg.persistence.git.author_email = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "persistence.git.default_branch")) {
            cfg.persistence.git.default_branch = try coerceStringDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "persistence.git.allow_paths")) {
            cfg.persistence.git.allow_paths = try coerceStringArrayDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "persistence.git.deny_paths")) {
            cfg.persistence.git.deny_paths = try coerceStringArrayDup(a, v);
            continue;
        }
        if (std.mem.eql(u8, k, "persistence.git.push_default")) {
            cfg.persistence.git.push_default = try coerceBool(v);
            continue;
        }
        if (std.mem.eql(u8, k, "persistence.git.remote_name")) {
            cfg.persistence.git.remote_name = try coerceStringDup(a, v);
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
                std.mem.eql(u8, field, "system_prompt") or
                std.mem.eql(u8, field, "provider") or
                std.mem.eql(u8, field, "provider_model") or
                std.mem.eql(u8, field, "provider_temperature") or
                std.mem.eql(u8, field, "provider_base_url") or
                std.mem.eql(u8, field, "provider_api_key_env"))
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

    if (cfg.gateway.rate_limit_window_ms == 0) {
        try warns.append(.{
            .key_path = try a.dupe(u8, "gateway.rate_limit_window_ms"),
            .message = try std.fmt.allocPrint(a, "rate_limit_window_ms={d} invalid; clamping to 1", .{cfg.gateway.rate_limit_window_ms}),
        });
        cfg.gateway.rate_limit_window_ms = 1;
    }

    if (cfg.gateway.rate_limit_max_requests == 0) {
        try warns.append(.{
            .key_path = try a.dupe(u8, "gateway.rate_limit_max_requests"),
            .message = try std.fmt.allocPrint(a, "rate_limit_max_requests={d} invalid; clamping to 1", .{cfg.gateway.rate_limit_max_requests}),
        });
        cfg.gateway.rate_limit_max_requests = 1;
    }

    if (cfg.automation.pickup_statuses.len == 0) {
        try warns.append(.{
            .key_path = try a.dupe(u8, "automation.pickup_statuses"),
            .message = try a.dupe(u8, "pickup_statuses cannot be empty; using [\"open\"]"),
        });
        cfg.automation.pickup_statuses = try dupeStrs(a, &.{"open"});
    }

    if (cfg.persistence.git.allow_paths.len == 0) {
        try warns.append(.{
            .key_path = try a.dupe(u8, "persistence.git.allow_paths"),
            .message = try a.dupe(u8, "allow_paths cannot be empty; using defaults"),
        });
        cfg.persistence.git.allow_paths = try dupeStrs(a, (PersistenceGitConfig{}).allow_paths);
    }
    if (cfg.persistence.git.remote_name.len == 0) {
        try warns.append(.{
            .key_path = try a.dupe(u8, "persistence.git.remote_name"),
            .message = try a.dupe(u8, "remote_name cannot be empty; using \"origin\""),
        });
        cfg.persistence.git.remote_name = try a.dupe(u8, "origin");
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

    // Build named provider pool
    {
        var np_names_list = std.array_list.Managed([]const u8).init(a);
        defer np_names_list.deinit();
        {
            var itnp = named_provider_names.keyIterator();
            while (itnp.next()) |kp| try np_names_list.append(kp.*);
        }
        std.sort.block([]const u8, np_names_list.items, {}, struct {
            fn lt(_: void, a_: []const u8, b_: []const u8) bool {
                return std.mem.lessThan(u8, a_, b_);
            }
        }.lt);

        var named_providers = std.array_list.Managed(NamedProviderConfig).init(a);
        errdefer {
            for (named_providers.items) |np| freeNamedProvider(a, np);
            named_providers.deinit();
        }

        for (np_names_list.items) |np_name| {
            const kind_key = try std.fmt.allocPrint(a, "providers.{s}.kind", .{np_name});
            defer a.free(kind_key);
            const model_key = try std.fmt.allocPrint(a, "providers.{s}.model", .{np_name});
            defer a.free(model_key);
            const temp_key = try std.fmt.allocPrint(a, "providers.{s}.temperature", .{np_name});
            defer a.free(temp_key);
            const url_key = try std.fmt.allocPrint(a, "providers.{s}.base_url", .{np_name});
            defer a.free(url_key);
            const apikey_key = try std.fmt.allocPrint(a, "providers.{s}.api_key", .{np_name});
            defer a.free(apikey_key);
            const vault_key = try std.fmt.allocPrint(a, "providers.{s}.api_key_vault", .{np_name});
            defer a.free(vault_key);
            const env_key = try std.fmt.allocPrint(a, "providers.{s}.api_key_env", .{np_name});
            defer a.free(env_key);

            var np_cfg = NamedProviderConfig{ .name = try a.dupe(u8, np_name) };
            errdefer freeNamedProvider(a, np_cfg);

            if (parsed.keys.map.get(kind_key)) |kv| {
                const s = try coerceString(kv);
                if (std.mem.eql(u8, s, "stub")) {
                    np_cfg.kind = .stub;
                } else if (std.mem.eql(u8, s, "openai_compat")) {
                    np_cfg.kind = .openai_compat;
                } else {
                    try warns.append(.{
                        .key_path = try a.dupe(u8, kind_key),
                        .message = try std.fmt.allocPrint(a, "unknown provider kind '{s}', using 'openai_compat'", .{s}),
                    });
                }
            }
            if (parsed.keys.map.get(model_key)) |mv| np_cfg.model = try coerceStringDup(a, mv);
            if (parsed.keys.map.get(temp_key)) |tv| np_cfg.temperature = try coerceF64(tv);
            if (parsed.keys.map.get(url_key)) |uv| np_cfg.base_url = try coerceStringDup(a, uv);
            if (parsed.keys.map.get(apikey_key)) |av| np_cfg.api_key = try coerceStringDup(a, av);
            if (parsed.keys.map.get(vault_key)) |vv| np_cfg.api_key_vault = try coerceStringDup(a, vv);
            if (parsed.keys.map.get(env_key)) |ev| np_cfg.api_key_env = try coerceStringDup(a, ev);

            try named_providers.append(np_cfg);
        }

        cfg.provider_named = try named_providers.toOwnedSlice();
    }

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
        const ag_provider_key = try std.fmt.allocPrint(a, "agents.{s}.provider", .{id});
        defer a.free(ag_provider_key);
        const ag_model_key = try std.fmt.allocPrint(a, "agents.{s}.provider_model", .{id});
        defer a.free(ag_model_key);
        const ag_temp_key = try std.fmt.allocPrint(a, "agents.{s}.provider_temperature", .{id});
        defer a.free(ag_temp_key);
        const ag_url_key = try std.fmt.allocPrint(a, "agents.{s}.provider_base_url", .{id});
        defer a.free(ag_url_key);
        const ag_env_key = try std.fmt.allocPrint(a, "agents.{s}.provider_api_key_env", .{id});
        defer a.free(ag_env_key);

        const preset_v = parsed.keys.map.get(preset_key);
        const delegate_v = parsed.keys.map.get(delegate_to_key);
        const prompt_v = parsed.keys.map.get(prompt_key);

        const capability_preset = if (preset_v) |pv| try coerceStringDup(a, pv) else try a.dupe(u8, cfg.capabilities.active_preset);
        const delegate_to = if (delegate_v) |dv| try coerceStringArrayDup(a, dv) else try dupeStrs(a, &.{});
        const system_prompt = if (prompt_v) |sv| try coerceStringDup(a, sv) else try a.dupe(u8, "");

        const ag_provider = if (parsed.keys.map.get(ag_provider_key)) |pv| try coerceStringDup(a, pv) else @as([]const u8, "");
        const ag_model = if (parsed.keys.map.get(ag_model_key)) |mv| try coerceStringDup(a, mv) else @as([]const u8, "");
        const ag_temp: ?f64 = if (parsed.keys.map.get(ag_temp_key)) |tv| try coerceF64(tv) else null;
        const ag_url = if (parsed.keys.map.get(ag_url_key)) |uv| try coerceStringDup(a, uv) else @as([]const u8, "");
        const ag_env = if (parsed.keys.map.get(ag_env_key)) |ev| try coerceStringDup(a, ev) else @as([]const u8, "");

        try agents.append(.{
            .id = try a.dupe(u8, id),
            .capability_preset = capability_preset,
            .delegate_to = delegate_to,
            .system_prompt = system_prompt,
            .provider = ag_provider,
            .provider_model = ag_model,
            .provider_temperature = ag_temp,
            .provider_base_url = ag_url,
            .provider_api_key_env = ag_env,
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

    // Validate agent provider references against named provider pool
    if (cfg.orchestration.agents.len > 0 and cfg.provider_named.len > 0) {
        for (cfg.orchestration.agents) |ag| {
            if (ag.provider.len > 0) {
                var found = false;
                for (cfg.provider_named) |np| {
                    if (std.mem.eql(u8, np.name, ag.provider)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    try warns.append(.{
                        .key_path = try std.fmt.allocPrint(a, "agents.{s}.provider", .{ag.id}),
                        .message = try std.fmt.allocPrint(a, "unknown named provider '{s}'", .{ag.provider}),
                    });
                }
            }
        }
    }

    try validatePresetToolsAgainstRegistry(a, cfg, &warns);
    try validateDelegationPresetSubsets(a, cfg, &warns);
    try validateExternalAllowList(a, cfg, &warns);

    return .{ .cfg = cfg, .warnings = try warns.toOwnedSlice() };
}

fn validatePresetToolsAgainstRegistry(a: std.mem.Allocator, cfg: Config, warns: *std.array_list.Managed(Warning)) !void {
    for (cfg.capabilities.presets) |preset| {
        for (preset.tools) |tool_name| {
            const entry = tools_registry.find(tool_name);
            if (entry == null) {
                if (cfg.tools.registry.strict) return error.UnregisteredTool;
                try warns.append(.{
                    .key_path = try std.fmt.allocPrint(a, "capabilities.presets.{s}.tools", .{preset.name}),
                    .message = try std.fmt.allocPrint(
                        a,
                        "tool '{s}' is not present in compiled ABI registry",
                        .{tool_name},
                    ),
                });
                continue;
            }

            if (entry.?.requires_network and !preset.allow_network) {
                if (cfg.tools.registry.strict) return error.NetworkToolRequiresPresetNetwork;
                try warns.append(.{
                    .key_path = try std.fmt.allocPrint(a, "capabilities.presets.{s}.allow_network", .{preset.name}),
                    .message = try std.fmt.allocPrint(
                        a,
                        "preset '{s}' includes network tool '{s}' but allow_network=false",
                        .{ preset.name, tool_name },
                    ),
                });
            }
        }
    }
}

fn validateDelegationPresetSubsets(a: std.mem.Allocator, cfg: Config, warns: *std.array_list.Managed(Warning)) !void {
    if (cfg.orchestration.agents.len == 0) return;

    for (cfg.orchestration.agents) |agent| {
        const parent_preset = findPresetByName(cfg.capabilities.presets, agent.capability_preset) orelse {
            if (cfg.tools.registry.strict) return error.UnknownCapabilityPreset;
            try warns.append(.{
                .key_path = try std.fmt.allocPrint(a, "agents.{s}.capability_preset", .{agent.id}),
                .message = try std.fmt.allocPrint(
                    a,
                    "agent '{s}' references unknown preset '{s}'",
                    .{ agent.id, agent.capability_preset },
                ),
            });
            continue;
        };

        const parent_caps = policy_algebra.CapabilityView{
            .tools = parent_preset.tools,
            .allow_network = parent_preset.allow_network,
            .write_paths = parent_preset.allow_write_paths,
        };

        for (agent.delegate_to) |target_id| {
            const target_agent = findAgentById(cfg.orchestration.agents, target_id) orelse continue;
            const child_preset = findPresetByName(cfg.capabilities.presets, target_agent.capability_preset) orelse {
                if (cfg.tools.registry.strict) return error.UnknownCapabilityPreset;
                try warns.append(.{
                    .key_path = try std.fmt.allocPrint(a, "agents.{s}.capability_preset", .{target_agent.id}),
                    .message = try std.fmt.allocPrint(
                        a,
                        "agent '{s}' references unknown preset '{s}'",
                        .{ target_agent.id, target_agent.capability_preset },
                    ),
                });
                continue;
            };

            const child_caps = policy_algebra.CapabilityView{
                .tools = child_preset.tools,
                .allow_network = child_preset.allow_network,
                .write_paths = child_preset.allow_write_paths,
            };

            if (!policy_algebra.isSubsetOf(child_caps, parent_caps)) {
                if (cfg.tools.registry.strict) return error.DelegationPresetEscalation;
                try warns.append(.{
                    .key_path = try std.fmt.allocPrint(a, "agents.{s}.delegate_to", .{agent.id}),
                    .message = try std.fmt.allocPrint(
                        a,
                        "delegate target '{s}' preset '{s}' is not a subset of '{s}'",
                        .{ target_agent.id, child_preset.name, parent_preset.name },
                    ),
                });
            }
        }
    }
}

fn validateExternalAllowList(a: std.mem.Allocator, cfg: Config, warns: *std.array_list.Managed(Warning)) !void {
    for (cfg.tools.filter.external_allow_list) |ext_tool| {
        // Warn if a built-in tool appears in external_allow_list (redundant)
        if (tools_registry.contains(ext_tool)) {
            try warns.append(.{
                .key_path = try a.dupe(u8, "tools.filter.external_allow_list"),
                .message = try std.fmt.allocPrint(
                    a,
                    "'{s}' is a built-in tool; listing it in external_allow_list is redundant",
                    .{ext_tool},
                ),
            });
            continue;
        }

        // Warn if tool is not referenced by any capability preset (dead entry)
        var referenced = false;
        for (cfg.capabilities.presets) |preset| {
            for (preset.tools) |t| {
                if (std.mem.eql(u8, t, ext_tool)) {
                    referenced = true;
                    break;
                }
            }
            if (referenced) break;
        }
        if (!referenced) {
            try warns.append(.{
                .key_path = try a.dupe(u8, "tools.filter.external_allow_list"),
                .message = try std.fmt.allocPrint(
                    a,
                    "'{s}' is not referenced by any capability preset",
                    .{ext_tool},
                ),
            });
        }
    }
}

fn findPresetByName(presets: []const PresetConfig, name: []const u8) ?PresetConfig {
    for (presets) |preset| {
        if (std.mem.eql(u8, preset.name, name)) return preset;
    }
    return null;
}

fn findAgentById(agents: []const AgentProfileConfig, id: []const u8) ?AgentProfileConfig {
    for (agents) |agent| {
        if (std.mem.eql(u8, agent.id, id)) return agent;
    }
    return null;
}

const str_util = @import("util/str.zig");

/// All known scalar config key paths used by buildTypedConfig.
const known_config_keys = [_][]const u8{
    "config_version",
    "meta.config_version",
    "vault_path",
    "capabilities.active_preset",
    "orchestration.leader_agent",
    "observability.enabled",
    "observability.dir",
    "observability.max_file_bytes",
    "observability.max_files",
    "logging.enabled",
    "logging.dir",
    "logging.file",
    "logging.max_file_bytes",
    "logging.max_files",
    "attestation.enabled",
    "replay.enabled",
    "gateway.rate_limit_enabled",
    "gateway.rate_limit_window_ms",
    "gateway.rate_limit_max_requests",
    "gateway.rate_limit_store",
    "gateway.rate_limit_dir",
    "security.workspace_root",
    "security.max_request_bytes",
    "tools.wasmtime_path",
    "tools.plugin_dir",
    "tools.external_dir",
    "tools.registry.strict",
    "tools.filter.allow_external",
    "tools.filter.external_allow_list",
    "queue.dir",
    "queue.poll_ms",
    "queue.max_retries",
    "queue.retry_backoff_ms",
    "queue.retry_jitter_pct",
    "providers.primary.kind",
    "providers.primary.model",
    "providers.primary.temperature",
    "providers.primary.base_url",
    "providers.primary.api_key",
    "providers.primary.api_key_vault",
    "providers.primary.api_key_env",
    "providers.fixtures.mode",
    "providers.fixtures.dir",
    "providers.fixtures.capsule_path",
    "providers.reliable.retries",
    "providers.reliable.backoff_ms",
    "memory.backend",
    "memory.root",
    "memory.primitives.enabled",
    "memory.primitives.templates_dir",
    "memory.primitives.strict_schema",
    "automation.task_pickup_enabled",
    "automation.default_owner",
    "automation.pickup_statuses",
    "persistence.git.enabled",
    "persistence.git.repo_dir",
    "persistence.git.author_name",
    "persistence.git.author_email",
    "persistence.git.default_branch",
    "persistence.git.allow_paths",
    "persistence.git.deny_paths",
    "persistence.git.push_default",
    "persistence.git.remote_name",
};

/// Known field suffixes for dynamic sections (agents.*, providers.*, presets.*).
const known_agent_fields = [_][]const u8{
    "capability_preset",
    "delegate_to",
    "system_prompt",
    "provider",
    "provider_model",
    "provider_temperature",
    "provider_base_url",
    "provider_api_key_env",
};

const known_named_provider_fields = [_][]const u8{
    "kind",
    "model",
    "temperature",
    "base_url",
    "api_key",
    "api_key_vault",
    "api_key_env",
};

const known_preset_fields = [_][]const u8{
    "tools",
    "allow_network",
    "allow_write_paths",
};

fn unknownKeyWarn(a: std.mem.Allocator, warns: *std.array_list.Managed(Warning), k: []const u8) !void {
    // Try to find a close match to suggest.
    const suggestion = findKeySuggestion(k);
    if (suggestion) |s| {
        try warns.append(.{
            .key_path = try a.dupe(u8, k),
            .message = try std.fmt.allocPrint(a, "unknown key (ignored); did you mean '{s}'?", .{s}),
        });
    } else {
        try warns.append(.{ .key_path = try a.dupe(u8, k), .message = try a.dupe(u8, "unknown key (ignored)") });
    }
}

fn findKeySuggestion(k: []const u8) ?[]const u8 {
    // For dynamic sections, check field suffixes.
    if (std.mem.startsWith(u8, k, "agents.")) {
        const rest = k["agents.".len..];
        if (std.mem.indexOfScalar(u8, rest, '.')) |dot| {
            const field = rest[dot + 1 ..];
            return str_util.closestMatch(field, &known_agent_fields, 2);
        }
    }
    if (std.mem.startsWith(u8, k, "capabilities.presets.")) {
        const rest = k["capabilities.presets.".len..];
        if (std.mem.indexOfScalar(u8, rest, '.')) |dot| {
            const field = rest[dot + 1 ..];
            return str_util.closestMatch(field, &known_preset_fields, 2);
        }
    }
    if (std.mem.startsWith(u8, k, "providers.")) {
        const rest = k["providers.".len..];
        if (!std.mem.startsWith(u8, rest, "primary.") and
            !std.mem.startsWith(u8, rest, "fixtures.") and
            !std.mem.startsWith(u8, rest, "reliable."))
        {
            if (std.mem.indexOfScalar(u8, rest, '.')) |dot| {
                const field = rest[dot + 1 ..];
                return str_util.closestMatch(field, &known_named_provider_fields, 2);
            }
        }
    }
    // Fall back to checking full key paths.
    return str_util.closestMatch(k, &known_config_keys, 2);
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
        .{ &cfg.vault_path, &d.vault_path },
        .{ &cfg.capabilities.active_preset, &d.capabilities.active_preset },
        .{ &cfg.observability.dir, &d.observability.dir },
        .{ &cfg.logging.dir, &d.logging.dir },
        .{ &cfg.logging.file, &d.logging.file },
        .{ &cfg.gateway.rate_limit_dir, &d.gateway.rate_limit_dir },
        .{ &cfg.security.workspace_root, &d.security.workspace_root },
        .{ &cfg.tools.wasmtime_path, &d.tools.wasmtime_path },
        .{ &cfg.tools.plugin_dir, &d.tools.plugin_dir },
        .{ &cfg.tools.external_dir, &d.tools.external_dir },
        .{ &cfg.queue.dir, &d.queue.dir },
        .{ &cfg.provider_primary.model, &d.provider_primary.model },
        .{ &cfg.provider_primary.base_url, &d.provider_primary.base_url },
        .{ &cfg.provider_primary.api_key, &d.provider_primary.api_key },
        .{ &cfg.provider_primary.api_key_vault, &d.provider_primary.api_key_vault },
        .{ &cfg.provider_primary.api_key_env, &d.provider_primary.api_key_env },
        .{ &cfg.provider_fixtures.dir, &d.provider_fixtures.dir },
        .{ &cfg.provider_fixtures.capsule_path, &d.provider_fixtures.capsule_path },
        .{ &cfg.memory.root, &d.memory.root },
        .{ &cfg.memory.primitives.templates_dir, &d.memory.primitives.templates_dir },
        .{ &cfg.automation.default_owner, &d.automation.default_owner },
        .{ &cfg.persistence.git.repo_dir, &d.persistence.git.repo_dir },
        .{ &cfg.persistence.git.author_name, &d.persistence.git.author_name },
        .{ &cfg.persistence.git.author_email, &d.persistence.git.author_email },
        .{ &cfg.persistence.git.default_branch, &d.persistence.git.default_branch },
        .{ &cfg.persistence.git.remote_name, &d.persistence.git.remote_name },
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

    if (cfg.provider_named.ptr != d.provider_named.ptr) {
        for (cfg.provider_named) |np| freeNamedProvider(a, np);
        a.free(cfg.provider_named);
    }

    if (cfg.automation.pickup_statuses.ptr != d.automation.pickup_statuses.ptr) {
        for (cfg.automation.pickup_statuses) |s| a.free(s);
        a.free(cfg.automation.pickup_statuses);
    }

    if (cfg.persistence.git.allow_paths.ptr != d.persistence.git.allow_paths.ptr) {
        for (cfg.persistence.git.allow_paths) |s| a.free(s);
        a.free(cfg.persistence.git.allow_paths);
    }
    if (cfg.persistence.git.deny_paths.ptr != d.persistence.git.deny_paths.ptr) {
        for (cfg.persistence.git.deny_paths) |s| a.free(s);
        a.free(cfg.persistence.git.deny_paths);
    }

    if (cfg.tools.filter.external_allow_list.ptr != d.tools.filter.external_allow_list.ptr) {
        for (cfg.tools.filter.external_allow_list) |s| a.free(s);
        a.free(cfg.tools.filter.external_allow_list);
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
    if (ag.provider.len > 0) a.free(ag.provider);
    if (ag.provider_model.len > 0) a.free(ag.provider_model);
    if (ag.provider_base_url.len > 0) a.free(ag.provider_base_url);
    if (ag.provider_api_key_env.len > 0) a.free(ag.provider_api_key_env);
}

fn freeNamedProvider(a: std.mem.Allocator, np: NamedProviderConfig) void {
    a.free(np.name);
    if (np.model.len > 0) a.free(np.model);
    if (np.base_url.len > 0) a.free(np.base_url);
    if (np.api_key.len > 0) a.free(np.api_key);
    if (np.api_key_vault.len > 0) a.free(np.api_key_vault);
    if (np.api_key_env.len > 0) a.free(np.api_key_env);
}

fn freeWarnings(a: std.mem.Allocator, warnings: []Warning) void {
    for (warnings) |w| {
        a.free(w.key_path);
        a.free(w.message);
    }
    if (warnings.len > 0) a.free(warnings);
}

// --------------------------------
// Semantic config diff
// --------------------------------

pub const DiffEntry = struct {
    key: []const u8,
    kind: enum { changed, added, removed },
    old_value: []const u8,
    new_value: []const u8,
};

/// Compare two config files semantically by parsing both into flat key maps and
/// reporting added, removed, and changed keys. Caller owns the returned slice
/// and all strings within it (allocated with `a`).
pub fn semanticDiff(a: std.mem.Allocator, io: std.Io, path_a: []const u8, path_b: []const u8) ![]DiffEntry {
    const content_a = try std.Io.Dir.cwd().readFileAlloc(io, path_a, a, std.Io.Limit.limited(1024 * 1024));
    defer a.free(content_a);
    const content_b = try std.Io.Dir.cwd().readFileAlloc(io, path_b, a, std.Io.Limit.limited(1024 * 1024));
    defer a.free(content_b);

    var parsed_a = try tomlParseKeyMap(a, content_a);
    defer parsed_a.deinit(a);
    var parsed_b = try tomlParseKeyMap(a, content_b);
    defer parsed_b.deinit(a);

    return diffKeyMaps(a, parsed_a.keys, parsed_b.keys);
}

fn diffKeyMaps(a: std.mem.Allocator, map_a: KeyMap, map_b: KeyMap) ![]DiffEntry {
    var entries = std.array_list.Managed(DiffEntry).init(a);
    errdefer {
        for (entries.items) |e| freeDiffEntry(a, e);
        entries.deinit();
    }

    // Collect all keys from both maps.
    var all_keys = std.StringHashMap(void).init(a);
    defer all_keys.deinit();

    {
        var it = map_a.map.iterator();
        while (it.next()) |e| try all_keys.put(e.key_ptr.*, {});
    }
    {
        var it = map_b.map.iterator();
        while (it.next()) |e| try all_keys.put(e.key_ptr.*, {});
    }

    // Sort keys for deterministic output.
    var sorted = std.array_list.Managed([]const u8).init(a);
    defer sorted.deinit();
    {
        var it = all_keys.keyIterator();
        while (it.next()) |kp| try sorted.append(kp.*);
    }
    std.sort.block([]const u8, sorted.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.lt);

    for (sorted.items) |key| {
        const in_a = map_a.map.get(key);
        const in_b = map_b.map.get(key);

        if (in_a != null and in_b != null) {
            const sa = try valueToString(a, in_a.?);
            defer a.free(sa);
            const sb = try valueToString(a, in_b.?);
            defer a.free(sb);
            if (!std.mem.eql(u8, sa, sb)) {
                try entries.append(.{
                    .key = try a.dupe(u8, key),
                    .kind = .changed,
                    .old_value = try a.dupe(u8, sa),
                    .new_value = try a.dupe(u8, sb),
                });
            }
        } else if (in_a != null and in_b == null) {
            const sa = try valueToString(a, in_a.?);
            try entries.append(.{
                .key = try a.dupe(u8, key),
                .kind = .removed,
                .old_value = sa,
                .new_value = try a.dupe(u8, ""),
            });
        } else if (in_a == null and in_b != null) {
            const sb = try valueToString(a, in_b.?);
            try entries.append(.{
                .key = try a.dupe(u8, key),
                .kind = .added,
                .old_value = try a.dupe(u8, ""),
                .new_value = sb,
            });
        }
    }

    return try entries.toOwnedSlice();
}

fn valueToString(a: std.mem.Allocator, v: Value) ![]u8 {
    return switch (v) {
        .string => |s| try std.fmt.allocPrint(a, "\"{s}\"", .{s}),
        .boolean => |b| try a.dupe(u8, if (b) "true" else "false"),
        .integer => |i| try std.fmt.allocPrint(a, "{d}", .{i}),
        .float => |f| try std.fmt.allocPrint(a, "{d}", .{f}),
        .array => |arr| blk: {
            var aw: std.Io.Writer.Allocating = .init(a);
            errdefer aw.deinit();
            try aw.writer.writeByte('[');
            for (arr, 0..) |item, idx| {
                if (idx != 0) try aw.writer.writeAll(", ");
                const s = try valueToString(a, item);
                defer a.free(s);
                try aw.writer.writeAll(s);
            }
            try aw.writer.writeByte(']');
            break :blk try aw.toOwnedSlice();
        },
    };
}

pub fn freeDiffEntries(a: std.mem.Allocator, entries: []DiffEntry) void {
    for (entries) |e| freeDiffEntry(a, e);
    if (entries.len > 0) a.free(entries);
}

fn freeDiffEntry(a: std.mem.Allocator, e: DiffEntry) void {
    a.free(e.key);
    a.free(e.old_value);
    a.free(e.new_value);
}

// --------------------------------
// JSON Schema generation
// --------------------------------

/// Generate a JSON Schema matching the zigclaw.toml file structure.
/// The schema reflects the TOML key hierarchy (e.g. [providers.primary])
/// rather than the Zig struct layout, enabling editor autocompletion
/// via Even Better TOML + schema association.
pub fn jsonSchemaAlloc(a: std.mem.Allocator) []u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    const w = &aw.writer;
    schemaWriteTomlLayout(w);
    return aw.toOwnedSlice() catch @panic("OOM generating config schema");
}

fn schemaWriteTomlLayout(w: anytype) void {
    w.writeAll(
        \\{
        \\  "$schema": "https://json-schema.org/draft/2020-12/schema",
        \\  "title": "ZigClaw Configuration",
        \\  "description": "Schema for zigclaw.toml configuration file",
        \\  "type": "object",
        \\  "properties": {
        \\    "config_version": {"type": "integer", "minimum": 1},
        \\    "vault_path": {"type": "string"},
        \\    "capabilities": {
        \\      "type": "object",
        \\      "properties": {
        \\        "active_preset": {"type": "string"},
        \\        "presets": {
        \\          "type": "object",
        \\          "additionalProperties": {
        \\            "type": "object",
        \\            "properties": {
        \\              "tools": {"type": "array", "items": {"type": "string"}},
        \\              "allow_network": {"type": "boolean"},
        \\              "allow_write_paths": {"type": "array", "items": {"type": "string"}}
        \\            },
        \\            "additionalProperties": false
        \\          }
        \\        }
        \\      }
        \\    },
        \\    "orchestration": {
        \\      "type": "object",
        \\      "properties": {
        \\        "leader_agent": {"type": "string"}
        \\      }
        \\    },
        \\    "agents": {
        \\      "type": "object",
        \\      "additionalProperties": {
        \\        "type": "object",
        \\        "properties": {
        \\          "capability_preset": {"type": "string"},
        \\          "delegate_to": {"type": "array", "items": {"type": "string"}},
        \\          "system_prompt": {"type": "string"},
        \\          "provider": {"type": "string"},
        \\          "provider_model": {"type": "string"},
        \\          "provider_temperature": {"type": "number"},
        \\          "provider_base_url": {"type": "string"},
        \\          "provider_api_key_env": {"type": "string"}
        \\        },
        \\        "additionalProperties": false
        \\      }
        \\    },
        \\    "observability":
    ) catch return;
    schemaWriteStructType(w, ObservabilityConfig, 3);
    w.writeAll(
        \\,
        \\    "logging":
    ) catch return;
    schemaWriteStructType(w, LoggingConfig, 3);
    w.writeAll(
        \\,
        \\    "attestation":
    ) catch return;
    schemaWriteStructType(w, AttestationConfig, 3);
    w.writeAll(
        \\,
        \\    "replay":
    ) catch return;
    schemaWriteStructType(w, ReplayConfig, 3);
    w.writeAll(
        \\,
        \\    "gateway":
    ) catch return;
    schemaWriteStructType(w, GatewayConfig, 3);
    w.writeAll(
        \\,
        \\    "security":
    ) catch return;
    schemaWriteStructType(w, SecurityConfig, 3);
    w.writeAll(
        \\,
        \\    "providers": {
        \\      "type": "object",
        \\      "properties": {
        \\        "primary":
    ) catch return;
    schemaWriteStructType(w, ProviderConfig, 5);
    w.writeAll(
        \\,
        \\        "fixtures":
    ) catch return;
    schemaWriteStructType(w, ProviderFixturesConfig, 5);
    w.writeAll(
        \\,
        \\        "reliable":
    ) catch return;
    schemaWriteStructType(w, ProviderReliableConfig, 5);
    w.writeAll(
        \\
        \\      },
        \\      "additionalProperties":
    ) catch return;
    schemaWriteStructType(w, NamedProviderConfig, 4);
    w.writeAll(
        \\
        \\    },
        \\    "memory": {
        \\      "type": "object",
        \\      "properties": {
        \\        "backend":
    ) catch return;
    schemaWriteEnumType(w, MemoryBackend);
    w.writeAll(
        \\,
        \\        "root": {"type": "string"},
        \\        "primitives":
    ) catch return;
    schemaWriteStructType(w, MemoryPrimitivesConfig, 5);
    w.writeAll(
        \\
        \\      }
        \\    },
        \\    "tools": {
        \\      "type": "object",
        \\      "properties": {
        \\        "wasmtime_path": {"type": "string"},
        \\        "plugin_dir": {"type": "string"},
        \\        "external_dir": {"type": "string"},
        \\        "registry": {
        \\          "type": "object",
        \\          "properties": {
        \\            "strict": {"type": "boolean"}
        \\          }
        \\        },
        \\        "filter": {
        \\          "type": "object",
        \\          "properties": {
        \\            "allow_external": {"type": "boolean"},
        \\            "external_allow_list": {"type": "array", "items": {"type": "string"}}
        \\          }
        \\        }
        \\      }
        \\    },
        \\    "queue":
    ) catch return;
    schemaWriteStructType(w, QueueConfig, 3);
    w.writeAll(
        \\,
        \\    "automation":
    ) catch return;
    schemaWriteStructType(w, AutomationConfig, 3);
    w.writeAll(
        \\,
        \\    "persistence": {
        \\      "type": "object",
        \\      "properties": {
        \\        "git":
    ) catch return;
    schemaWriteStructType(w, PersistenceGitConfig, 5);
    w.writeAll(
        \\
        \\      }
        \\    }
        \\  },
        \\  "additionalProperties": false
        \\}
    ) catch return;
}

fn schemaWriteStructType(w: anytype, comptime T: type, comptime indent: usize) void {
    const fields = @typeInfo(T).@"struct".fields;
    w.writeAll(" {\n") catch return;
    schemaIndent(w, indent);
    w.writeAll("\"type\": \"object\",\n") catch return;
    schemaIndent(w, indent);
    w.writeAll("\"properties\": {\n") catch return;
    inline for (fields, 0..) |field, idx| {
        // Skip fields not relevant to TOML (e.g. 'name' in NamedProviderConfig is the table key)
        if (comptime std.mem.eql(u8, field.name, "name") and T == NamedProviderConfig) continue;
        schemaIndent(w, indent + 1);
        w.print("\"{s}\": ", .{field.name}) catch return;
        schemaWriteFieldType(w, field.type);
        if (idx < fields.len - 1) {
            w.writeAll(",\n") catch return;
        } else {
            w.writeAll("\n") catch return;
        }
    }
    schemaIndent(w, indent);
    w.writeAll("},\n") catch return;
    schemaIndent(w, indent);
    w.writeAll("\"additionalProperties\": false\n") catch return;
    schemaIndent(w, indent - 1);
    w.writeAll("}") catch return;
}

fn schemaWriteFieldType(w: anytype, comptime T: type) void {
    const info = @typeInfo(T);
    switch (info) {
        .bool => w.writeAll("{\"type\": \"boolean\"}") catch return,
        .int => |i| {
            if (i.signedness == .signed) {
                w.writeAll("{\"type\": \"integer\"}") catch return;
            } else {
                w.print("{{\"type\": \"integer\", \"minimum\": 0}}", .{}) catch return;
            }
        },
        .float => w.writeAll("{\"type\": \"number\"}") catch return,
        .@"enum" => schemaWriteEnumType(w, T),
        .pointer => |p| {
            if (p.size == .slice) {
                if (p.child == u8) {
                    w.writeAll("{\"type\": \"string\"}") catch return;
                } else {
                    w.writeAll("{\"type\": \"array\", \"items\": {\"type\": \"string\"}}") catch return;
                }
            } else {
                w.writeAll("{}") catch return;
            }
        },
        .optional => |o| schemaWriteFieldType(w, o.child),
        else => w.writeAll("{}") catch return,
    }
}

fn schemaWriteEnumType(w: anytype, comptime T: type) void {
    const fields = @typeInfo(T).@"enum".fields;
    w.writeAll("{\"type\": \"string\", \"enum\": [") catch return;
    inline for (fields, 0..) |field, idx| {
        w.print("\"{s}\"", .{field.name}) catch return;
        if (idx < fields.len - 1) w.writeAll(", ") catch return;
    }
    w.writeAll("]}") catch return;
}

fn schemaIndent(w: anytype, comptime n: usize) void {
    inline for (0..n) |_| {
        w.writeAll("  ") catch return;
    }
}

/// Write an inline comment for a key, if one was captured from the original file.
/// Emits " # <comment text>" (no trailing newline).
fn writeInlineComment(w: *std.Io.Writer, cm: CommentMap, key: []const u8) std.Io.Writer.Error!void {
    const comment = cm.getInline(key) orelse return;
    if (comment.len > 0) {
        try w.writeAll(" # ");
        try w.writeAll(comment);
    }
}

/// Write block comment lines for a section header, if any were captured.
/// Uses the "@section.path" convention from the parser for section-level comments.
fn writeSectionComment(w: *std.Io.Writer, cm: CommentMap, section: []const u8) std.Io.Writer.Error!void {
    // Build the lookup key with @ prefix.
    var key_buf: [128]u8 = undefined;
    if (section.len + 1 > key_buf.len) return;
    key_buf[0] = '@';
    @memcpy(key_buf[1..][0..section.len], section);
    const lookup = key_buf[0 .. section.len + 1];

    const comment = cm.block_comments.get(lookup) orelse return;
    // Emit each line as a TOML comment.
    var comment_lines = std.mem.splitScalar(u8, comment, '\n');
    while (comment_lines.next()) |cline| {
        try w.writeAll("# ");
        try w.writeAll(cline);
        try w.writeAll("\n");
    }
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
