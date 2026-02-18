# ZigClaw Agent System - User Guide

ZigClaw is a local-first agent runtime written in Zig. It assembles a prompt from
configuration, workspace context, and memory, sends it to a provider, executes any
tool calls the model returns, and iterates until the model stops calling tools or a
turn limit is reached. Everything runs on the local machine; the only network call
is the optional provider request.

This guide covers the agent loop architecture, single-agent and multi-agent usage,
configuration, common workflows, and troubleshooting.

---

## 1. Agent Basics

### Loop Architecture

Every agent run follows the same cycle:

1. **Prompt assembly** - The system prompt is built from the active config: identity
   line ("You are ZigClaw."), workspace root, active capability preset name, policy
   hash, allowed tools list (sorted alphabetically), a workspace file snapshot (paths,
   sizes, SHA-256 hashes), and the contents of three optional special files
   (`AGENTS.md`, `SOUL.md`, `TOOLS.md`, each truncated at 16 KB). Memory items are
   recalled (top 5 by relevance) and folded into a separate system-level context
   block.

2. **Provider call** - The assembled messages and tool definitions are sent to the
   configured provider (`stub` for testing, `openai_compat` for real models).

3. **Tool execution** - If the provider returns `tool_calls`, each call is dispatched
   through the tool runner. The runner checks the policy before execution and logs a
   decision event for every gate (tool allowance, network access).

4. **Iteration** - Steps 2-3 repeat until the provider returns a response with no
   tool calls, or the loop reaches the maximum of **10 turns**
   (`max_agent_turns = 10` in `src/agent/loop.zig:13`).

If the turn limit is exhausted the agent returns the message
`"Agent reached maximum number of turns without completing."`.

### Prompt Hash and Policy Hash

Every run computes two SHA-256 hashes. The **prompt hash** covers the system prompt,
user message, and recalled memory items. The **policy hash** covers the compiled
capability preset (tools, network flag, write paths). Both hashes appear in
observability logs and decision log events, enabling you to trace exactly which prompt
and policy were active for any given run.

---

## 2. Single-Agent Usage

When no `[orchestration]` section is configured (or `orchestration.agents` is empty),
ZigClaw runs in single-agent mode. The agent is called `"default"` and uses the
`active_preset` from `[capabilities]`.

### chat - Primary Entry Point

`zigclaw chat` is the recommended way to interact with the agent. It supports three
input modes in one command:

```sh
zigclaw chat                          # interactive session
zigclaw chat "Summarize README.md"    # one-shot with positional argument
zigclaw chat --message "Summarize README.md"  # one-shot with flag
echo "What does this do?" | zigclaw chat      # one-shot from stdin pipe
```

Runtime overrides (take precedence over config file):
```sh
zigclaw chat --model gpt-4.1 --preset dev "Write a test"
zigclaw chat --agent planner          # select a specific agent profile
zigclaw chat --json "Summarize"       # machine-readable output (one-shot only)
```

**Zero-config:** if `providers.primary.kind` is `stub` and `OPENAI_API_KEY` is set,
`chat` auto-switches to `openai_compat` with model `gpt-4.1-mini`.

### Interactive Session

The interactive session (`zigclaw chat` with no message argument, or
`zigclaw agent --interactive`) starts a REPL with conversation history retained
across turns:

- The prompt shows the active model: `[gpt-4.1-mini] > `
- Each user message and assistant response is appended to a message list, capped at
  40 entries (20 user/assistant pairs). All prior turns are sent to the model on
  each new message, giving it full conversation context.
- Token usage is printed to stderr after each response: `[N tokens in, N tokens out]`
- Type `quit` or `exit` to leave.
- If input exceeds the 4 KB line buffer the REPL prints `(input too long, try again)`
  and discards the line.

Slash commands available in the session:

| Command | Effect |
|---------|--------|
| `/help` | List available commands |
| `/model` | Show the active model name |
| `/turns` | Show turn count and history size |
| `/clear` | Reset conversation history |

### One-Shot Mode

```
zigclaw agent --message "Summarize README.md" --config zigclaw.toml
```

Output format:

```
request_id=req_abc123
turns=2
<model response content>
```

The `--config` flag defaults to `zigclaw.toml` in the current directory.

### Verbose Mode

Add `--verbose` to see turn-by-turn detail on stderr:

```
zigclaw agent --message "List files" --verbose
```

Stderr output includes request ID, model name, tool count, memory item count,
system prompt size, per-turn finish reason, content byte count, tool call count,
and token usage (prompt/completion/total).

### Capability Presets

The default scaffold (`zigclaw init`) creates two presets:

**readonly** - Safe read-only access.
```toml
[capabilities.presets.readonly]
tools = ["echo"]
allow_network = false
allow_write_paths = []
```

**dev** - Broader toolset with network and write access.
```toml
[capabilities.presets.dev]
tools = ["echo", "fs_read", "fs_write", "shell_exec", "http_fetch"]
allow_network = true
allow_write_paths = ["./.zigclaw", "./tmp"]
```

The active preset is selected in `[capabilities]`:
```toml
[capabilities]
active_preset = "readonly"
```

If `allow_network` is `false` and the provider requires network access (i.e. the
provider kind is `openai_compat`), the agent returns `error.ProviderNetworkNotAllowed`
before making any provider call.

---

## 3. Multi-Agent Orchestration

Multi-agent mode is activated by adding agent profiles. When agents are configured,
ZigClaw uses static delegation: a leader agent can delegate sub-tasks to other agents
through a synthetic tool call.

### Configuration

```toml
[orchestration]
leader_agent = "planner"

[agents.planner]
capability_preset = "readonly"
delegate_to = ["writer"]
system_prompt = "Break work into steps and delegate."

[agents.writer]
capability_preset = "dev"
delegate_to = []
system_prompt = "Implement delegated tasks."
```

**Fields per agent:**

- `capability_preset` - Which preset to use. If the agent's preset differs from
  the global `active_preset`, policy is recompiled for that agent.
- `delegate_to` - List of agent IDs this agent may call. An empty list means no
  delegation.
- `system_prompt` - Appended after the base system prompt as an additional system
  message.

### Multi-Model Provider Selection

By default, every agent uses `[providers.primary]`. You can override this per-agent
using named providers and inline fields. The resolution priority is (lowest to highest):

1. `[providers.primary]` - global default
2. Named provider (`provider = "capable"`) - inherits from a `[providers.NAME]` block
3. Inline agent fields (`provider_model`, `provider_temperature`, etc.) - highest priority

**Named provider pool:** define additional providers alongside `[providers.primary]`:

```toml
[providers.primary]
kind = "openai_compat"
model = "gpt-4.1-mini"
api_key_env = "OPENAI_API_KEY"

[providers.capable]
kind = "openai_compat"
model = "gpt-4.1"
temperature = 0.3
api_key_env = "OPENAI_API_KEY"
```

**Per-agent provider assignment:** reference a named provider by name, or override
individual fields inline:

```toml
[agents.planner]
capability_preset = "readonly"
delegate_to = ["writer"]
system_prompt = "Break work into steps and delegate."
# Uses providers.primary (default) - cheap model for planning

[agents.writer]
capability_preset = "dev"
delegate_to = []
system_prompt = "Implement delegated tasks."
provider = "capable"           # use the named provider
```

**Inline overrides** take precedence over the named provider. This lets you use a
named provider as a base and tweak specific fields per agent:

```toml
[agents.reviewer]
capability_preset = "readonly"
delegate_to = []
system_prompt = "Review the implementation."
provider = "capable"
provider_temperature = 0.1     # override the named provider's temperature
```

You can also use inline overrides without a named provider at all:

```toml
[agents.writer]
capability_preset = "dev"
delegate_to = []
system_prompt = "Implement delegated tasks."
provider_model = "gpt-4.1"
provider_temperature = 0.8
```

**Agent provider fields:**

- `provider` - Name of a `[providers.NAME]` block to use as base.
- `provider_model` - Override the model name.
- `provider_temperature` - Override temperature (note: 0.0 is a valid override).
- `provider_base_url` - Override the base URL.
- `provider_api_key_env` - Override the API key environment variable name.

**API key management:** when using multiple providers that require different API keys,
set each provider's `api_key_env` to a distinct environment variable name. The
`zigclaw init` wizard will list all required environment variables in the next-steps
output.

**Decision log:** the `provider.select` event now includes agent context in the reason
field: `agent=writer kind=openai_compat model=gpt-4.1`. This makes it straightforward
to verify which model was used for each agent in a multi-agent run.

### The `delegate_agent` Tool

When `delegate_to` is non-empty, a synthetic tool called `delegate_agent` is injected
into the agent's available tools. Its schema:

```json
{
  "type": "object",
  "required": ["target_agent", "message"],
  "properties": {
    "target_agent": {
      "type": "string",
      "enum": ["writer"]
    },
    "message": {
      "type": "string",
      "max_length": 8192
    }
  }
}
```

The `enum` for `target_agent` is populated from the agent's `delegate_to` list. The
tool description reads: `"Delegate work to another configured agent. Allowed targets:
@writer"`.

### Delegation Depth

Delegation is recursive but bounded. The maximum depth is **3**
(`default_max_delegate_depth = 3` in `src/agent/loop.zig:14`). Each delegation
increments `delegate_depth` by 1. Child agents inherit the cancel check and request
ID from the parent, but `interactive` is forced to `false`.

### Agent Resolution

When a run starts, the active agent is resolved in this order:

1. If `--agent <id>` was passed (or `agent_id` in RunOptions), use that ID.
2. Otherwise, if `orchestration.leader_agent` is set, use it.
3. Otherwise, use the first agent in alphabetical order.
4. If no agents are configured at all, use the implicit `"default"` agent with no
   profile.

If the requested agent ID does not match any configured agent, the error
`UnknownAgent` is returned.

### Delegation Errors

- `DelegateNotAllowed` - The calling agent has no profile or its `delegate_to` is
  empty.
- `DelegateDepthExceeded` - The delegation chain has reached the maximum depth of 3.
- `DelegateTargetDenied` - The target agent is not listed in the caller's
  `delegate_to`.
- `UnknownAgent` - The target agent ID does not match any `[agents.*]` section.

---

## 4. Configuration Deep-Dive

All configuration lives in `zigclaw.toml`. Run `zigclaw init` to generate a scaffold
with defaults. Run `zigclaw config validate` to parse, validate, and print the
normalized config.

### Capabilities and Presets

```toml
[capabilities]
active_preset = "readonly"

[capabilities.presets.readonly]
tools = ["echo"]
allow_network = false
allow_write_paths = []

[capabilities.presets.dev]
tools = ["echo", "fs_read", "fs_write", "shell_exec", "http_fetch"]
allow_network = true
allow_write_paths = ["./.zigclaw", "./tmp"]
```

- `active_preset` - Names the default preset. Defaults to `"readonly"`.
- `tools` - List of tool names the agent is allowed to call. Each name must match a
  `.toml` manifest in `tools.plugin_dir`.
- `allow_network` - Whether tools and the provider may make network requests.
- `allow_write_paths` - Directories the agent may write to. Paths are resolved
  relative to `security.workspace_root`.

If no presets are defined, a minimal `readonly` preset is synthesized with
`tools = ["echo"]`, no network, and no write paths.

### Provider Configuration

```toml
[providers.primary]
kind = "openai_compat"     # "stub" | "openai_compat"
model = "gpt-4.1-mini"
temperature = 0.2
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
# optional vault key name (prompts for passphrase on use)
# api_key_vault = "openai_api_key"

[providers.fixtures]
mode = "off"               # "off" | "record" | "replay" | "capsule_replay"
dir = "./.zigclaw/fixtures"
capsule_path = ""          # required when mode = "capsule_replay"

[providers.reliable]
retries = 0
backoff_ms = 250
```

The `stub` provider returns canned responses without network access - useful for
development and testing. `openai_compat` calls an OpenAI-compatible API. The API key
resolution order is: inline `api_key`, then vault key `api_key_vault`, then env var
named in `api_key_env`.

**Zero-config auto-detection:** when `kind = "stub"` and `OPENAI_API_KEY` is set in
the environment, `zigclaw chat` and `zigclaw agent` automatically switch to
`openai_compat` with model `gpt-4.1-mini`. Useful for ad-hoc use without editing
`zigclaw.toml`.

**Environment variable overrides** apply between the config file and CLI flags:
- `ZIGCLAW_MODEL` - overrides `providers.primary.model`
- `ZIGCLAW_BASE_URL` - overrides `providers.primary.base_url`

The fixtures wrapper records or replays provider responses for deterministic testing.
The reliable wrapper retries failed provider calls with exponential backoff.

### Attestation and Replay

```toml
[attestation]
enabled = false

[replay]
enabled = false
```

When attestation is enabled, runs emit Merkle-based receipts under
`.zigclaw/receipts/<request_id>.json`. When replay is enabled, runs emit replay
capsules under `.zigclaw/capsules/<request_id>.json`.

### Security

```toml
[security]
workspace_root = "."
max_request_bytes = 262144
```

`workspace_root` anchors all path resolution. `max_request_bytes` (default 256 KB)
limits the size of incoming gateway requests.

### Queue

```toml
[queue]
dir = "./.zigclaw/queue"
poll_ms = 1000
max_retries = 2
retry_backoff_ms = 500
retry_jitter_pct = 20
```

The queue is file-based, using subdirectories: `incoming`, `processing`, `outgoing`,
`canceled`, and `cancel_requests`. `retry_backoff_ms` is the base delay for
exponential backoff on retries. `retry_jitter_pct` adds deterministic jitter (0-100,
clamped) computed via Wyhash of the request ID and attempt number.

### Gateway

```toml
[gateway]
rate_limit_enabled = false
rate_limit_store = "memory"    # "memory" | "file"
rate_limit_window_ms = 1000
rate_limit_max_requests = 60
rate_limit_dir = "./.zigclaw/gateway_rate_limit"
```

The gateway exposes the agent runtime over HTTP. Rate limiting uses a fixed-window
token bucket. The `memory` store uses 128 static in-process buckets keyed by client
identity (bearer token, `X-Client-Id` header, or `X-Forwarded-For`). The `file` store
writes event files to disk for multi-process sharing.

### Observability and Decision Logging

```toml
[observability]
enabled = true
dir = "./.zigclaw/logs"
max_file_bytes = 1048576
max_files = 5

[logging]
enabled = true
dir = "./.zigclaw"
file = "decisions.jsonl"
max_file_bytes = 1048576
max_files = 5
```

Observability logs go to `.zigclaw/logs/zigclaw.jsonl` as structured JSONL with
event kinds: `gateway_request`, `queue_job`, `tool_run`, `agent_run`, `provider_call`,
`err`.

Decision logs go to `.zigclaw/decisions.jsonl`. Each line is a `DecisionEvent` with
fields: `ts_unix_ms`, `request_id`, `prompt_hash` (nullable), `decision`, `subject`,
`allowed`, `reason`, `policy_hash`. Both log types support rotation: when a file
exceeds `max_file_bytes`, existing files are shifted by numbered suffix (`.1`, `.2`,
etc.) and the oldest is evicted when `max_files` is reached.

### Memory

```toml
[memory]
backend = "markdown"       # "markdown" | "sqlite"
root = "./.zigclaw/memory"

[memory.primitives]
enabled = true
templates_dir = "./.zigclaw/memory/templates"
strict_schema = true
```

Memory recall fetches the top 5 items relevant to the user message. Items are
presented in the system prompt under a `[Memory context]` block.

### Orchestration (Multi-Agent)

```toml
[orchestration]
leader_agent = "planner"

[providers.capable]
kind = "openai_compat"
model = "gpt-4.1"
temperature = 0.3
api_key_env = "OPENAI_API_KEY"

[agents.planner]
capability_preset = "readonly"
delegate_to = ["writer"]
system_prompt = "Break work into steps and delegate."

[agents.writer]
capability_preset = "dev"
delegate_to = []
system_prompt = "Implement delegated tasks."
provider = "capable"
```

See section 3 above for semantics, including per-agent provider overrides via named
providers and inline fields. If `leader_agent` is empty but agents are defined,
the first agent alphabetically becomes the leader. If the named leader is not found in
`[agents.*]`, a config warning is emitted and the first agent is used.

---

## 5. Common Workflows

### One-Shot Query

```
zigclaw chat "Explain the build system"
```

Returns the model's response to stdout. Add `--json` for machine-readable output
including `request_id`, `turns`, and `content`.

For legacy one-shot use via `agent`:
```
zigclaw agent --message "Explain the build system"
```

Output includes `request_id=...` and `turns=...` on the first two lines.

### Interactive Session

```
zigclaw chat
```

Starts a persistent conversation. History is retained across turns (up to 20 pairs).
Use `/clear` to reset, `/turns` to inspect history depth, `quit` to exit.

For `agent`-style REPL (same behavior, no persistent history between sessions):
```
zigclaw agent --interactive
```

### Multi-Agent Delegation

With a planner/writer config:

```
zigclaw agent --message "Add input validation to the form handler"
```

The planner agent receives the message, breaks it into steps, and calls
`delegate_agent` with target `"writer"` and a focused sub-task message. The writer
runs with the `dev` preset, executes tools, and returns its result. The planner
synthesizes the final response.

### Async Queue Workflow

Enqueue a job:
```
zigclaw queue enqueue-agent --message "Run nightly analysis" --request-id req_1
```

Run the worker (process one job):
```
zigclaw queue worker --once
```

Check status:
```
zigclaw queue status --request-id req_1
```

Include the result payload:
```
zigclaw queue status --request-id req_1 --include-payload
```

Cancel a job:
```
zigclaw queue cancel --request-id req_1
```

View queue metrics:
```
zigclaw queue metrics
```

Metrics return counts for: `incoming_total`, `incoming_ready`, `incoming_delayed`,
`processing`, `outgoing`, `canceled`, `cancel_markers`.

### Continuous Worker

```
zigclaw queue worker --poll-ms 500 --max-jobs 100
```

The worker polls the incoming directory at the specified interval and processes jobs
until `max-jobs` is reached or no more jobs are available (if `--once` is set). Failed
jobs are retried with exponential backoff up to `max_retries`.

### Gateway HTTP API

Start the gateway:
```
zigclaw gateway start --port 8787
```

Endpoints:

- `POST /v1/agent/enqueue` - Enqueue an async agent job (returns 202).
- `GET /v1/requests/<id>` - Get job status.
- `POST /v1/requests/<id>/cancel` - Cancel a job.
- `GET /v1/queue/metrics` - Get queue metrics.
- `POST /v1/agent` - Synchronous agent run (blocks until complete).

### Prompt Inspection

Dump the assembled prompt (useful for debugging what the model sees):
```
zigclaw prompt dump --message "test" --format text
```

Output includes prompt hash, policy hash, full system prompt, user message, and
recalled memory items. JSON format is also available (`--format json`).

Compare two prompt dumps:
```
zigclaw prompt diff --a dump1.json --b dump2.json
```

### Policy Inspection

Print the current policy hash:
```
zigclaw policy hash
```

Explain whether a specific tool is allowed and why:
```
zigclaw policy explain --tool fs_read
```

Check if a filesystem path is accessible:
```
zigclaw policy explain --mount /some/path
```

Check if a shell command is safe:
```
zigclaw policy explain --command "ls -la"
```

Only one of `--tool`, `--mount`, or `--command` may be provided per invocation.

---

## 6. Troubleshooting

### Tool Denied

If a tool call is rejected, verify:

1. The `active_preset` in `[capabilities]` matches the intended preset.
2. The tool name appears in that preset's `tools` array.
3. The tool manifest exists in `tools.plugin_dir` (default `./zig-out/bin/<name>.toml`).

Use `zigclaw policy explain --tool <name>` to see the current allow/deny reasoning.

### Network Denied

If the agent returns `ProviderNetworkNotAllowed`, the active preset has
`allow_network = false` but the provider kind is `openai_compat` (which requires
network access). Either switch to the `stub` provider or use a preset with
`allow_network = true`. In interactive mode, a hint is printed inline:
`hint: The active preset disallows network access. Use --preset or edit zigclaw.toml`.

For tool-level network denial, check the `tool.network` decision category in the
decision log.

### Delegation Errors

- **DelegateNotAllowed** - The agent has no profile or `delegate_to` is empty. Add a
  `delegate_to` list to the agent's config.
- **DelegateDepthExceeded** - The chain of delegations has reached depth 3. Flatten
  the delegation graph or increase `max_delegate_depth` (requires source change,
  constant at `src/agent/loop.zig:14`).
- **DelegateTargetDenied** - The target agent is not in the caller's `delegate_to`.
  Add the target to the list.
- **UnknownAgent** - The agent ID does not exist. Check for typos in `delegate_to`
  and `[agents.*]` section names.

### Decision Log Inspection

Decision events are written to `.zigclaw/decisions.jsonl`. Each line is a JSON object:

```json
{
  "ts_unix_ms": 1700000000000,
  "request_id": "req_abc",
  "prompt_hash": "a1b2c3...",
  "decision": "tool.allow",
  "subject": "fs_read",
  "allowed": true,
  "reason": "tool is in active preset tools list",
  "policy_hash": "d4e5f6..."
}
```

Decision categories logged throughout the system:

- `tool.allow` - Whether a tool call was permitted by the preset.
- `tool.network` - Whether a tool's network access was permitted.
- `provider.network` - Whether the provider was allowed to make network calls.
- `provider.select` - Which provider and model were selected for the run. Reason
  includes `agent=`, `kind=`, and `model=` fields for multi-model tracing.
- `provider.fixtures` - Whether the fixtures wrapper is active.
- `provider.reliable` - Whether the reliable retry wrapper is active.
- `memory.backend` - Which memory backend was used.
- `memory.recall` - That memory recall was executed.
- `gateway.auth` - Whether a gateway request passed authentication.
- `gateway.request_bytes` - Request size boundary check.
- `gateway.throttle` - Whether a request was rate-limited.

### Observability Log Inspection

Observability events are written to `.zigclaw/logs/zigclaw.jsonl`. Event kinds:

- `agent_run` - Agent loop start, completion, cancellation, max turns reached.
- `provider_call` - Each provider request (start, ok, error) with token counts.
- `tool_run` - Each tool execution (start, ok, error).
- `queue_job` - Queue worker job lifecycle events.
- `gateway_request` - HTTP gateway request/response events.
- `err` - General errors.

### Queue Job Stuck in Processing

If a job stays in the `processing` directory, it likely means the worker process
crashed or was killed mid-run. Move the file back to `incoming` to requeue it, or
delete it if the job is no longer needed. The file naming convention is
`<timestamp_ms>_<request_id>.json`.

### Config Tooling

Generate a JSON Schema for editor autocompletion:
```
zigclaw config schema > zigclaw-schema.json
```

The schema covers all config sections and fields with types, enums, and defaults. Pair
it with VS Code's Even Better TOML extension (or similar) for real-time validation and
autocompletion while editing `zigclaw.toml`.

Compare two config files semantically:
```
zigclaw config diff --a zigclaw.toml --b zigclaw-prod.toml
zigclaw config diff --a zigclaw.toml --b zigclaw-prod.toml --json
```

Output shows added, removed, and changed keys with their values. JSON mode returns a
structured array of `{key, kind, old, new}` entries.

### Config Validation

Run `zigclaw config validate` to check for parse errors and warnings. Inline comments
from the original file are preserved through the round-trip. Common warnings:

- `unknown key (ignored)` - A TOML key that does not map to any config field. When a
  close match exists (Levenshtein distance <= 2), a "did you mean?" suggestion is
  appended to the warning.
- `retry_jitter_pct out of range; clamping to 100` - Value was greater than 100.
- `rate_limit_window_ms invalid; clamping to 1` - Value was 0.
- `leader not found in [agents.*]` - The named leader agent does not exist.
- `unknown delegate target` - An agent's `delegate_to` references a nonexistent agent.
- `unknown named provider` - An agent's `provider` references a `[providers.NAME]`
  section that does not exist.

### Verifying Policy Hash

The policy hash changes whenever the active preset's tools, network flag, or write
paths change. Use `zigclaw policy hash` before and after config changes to confirm
the policy was recompiled. Compare it against `policy_hash` values in the decision
log to verify which policy was active during a specific run.
