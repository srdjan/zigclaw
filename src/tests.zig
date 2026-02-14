const std = @import("std");
const commands = @import("security/commands.zig");
const pairing = @import("security/pairing.zig");
const config = @import("config.zig");

test "commands.isCommandSafe denies separators" {
    try std.testing.expect(commands.isCommandSafe("ls -la"));
    try std.testing.expect(!commands.isCommandSafe("ls; rm -rf /"));
    try std.testing.expect(!commands.isCommandSafe("echo hi && whoami"));
}

test "pairing.constantTimeEq basic" {
    try std.testing.expect(pairing.constantTimeEq("abc", "abc"));
    try std.testing.expect(!pairing.constantTimeEq("abc", "abd"));
    try std.testing.expect(!pairing.constantTimeEq("abc", "ab"));
}

test "config validate emits stable normalized TOML" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const vc = try config.loadAndValidate(a, "zigclaw.toml");
    defer vc.deinit(a);

    var out = std.ArrayList(u8).init(a);
    defer out.deinit();

    try vc.printNormalizedToml(out.writer());

    const expected = try std.fs.cwd().readFileAlloc(a, "tests/golden/config_normalized.toml", 1024 * 1024);
    defer a.free(expected);

    try std.testing.expectEqualStrings(expected, out.items);
}

test "policy explain outputs stable JSON (except hash)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const vc = try config.loadAndValidate(a, "zigclaw.toml");
    defer vc.deinit(a);

    const out = try vc.policy.explainToolJsonAlloc(a, "fs_read");
    defer a.free(out);

    const expected0 = try std.fs.cwd().readFileAlloc(a, "tests/golden/policy_explain_fs_read.json", 1024 * 1024);
    defer a.free(expected0);

    // Replace placeholder with actual hash
    const placeholder = "__POLICY_HASH__";
    const idx = std.mem.indexOf(u8, expected0, placeholder) orelse return error.BadGolden;
    var expected = try a.alloc(u8, expected0.len - placeholder.len + vc.policy.policyHash().len);
    defer a.free(expected);

    std.mem.copyForwards(u8, expected[0..idx], expected0[0..idx]);
    std.mem.copyForwards(u8, expected[idx..][0..vc.policy.policyHash().len], vc.policy.policyHash());
    const tail_src = idx + placeholder.len;
    const tail_dst = idx + vc.policy.policyHash().len;
    std.mem.copyForwards(u8, expected[tail_dst..], expected0[tail_src..]);

    try std.testing.expectEqualStrings(expected, out);
}

const tool_manifest = @import("tools/manifest.zig");
const tool_schema = @import("tools/schema.zig");

test "manifest load + args schema validation (echo)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    var owned = try tool_manifest.loadManifest(a, "tests/fixtures/echo.toml");
    defer owned.deinit(a);

    // valid
    try tool_schema.validateArgs(owned.manifest.args, "{\"text\":\"hi\"}");

    // missing required
    try std.testing.expectError(tool_schema.ValidationError.MissingRequired, tool_schema.validateArgs(owned.manifest.args, "{}"));

    // too long
    var big = try a.alloc(u8, 1100);
    defer a.free(big);
    @memset(big, 'a');
    const args = try std.fmt.allocPrint(a, "{{\"text\":\"{s}\"}}", .{big});
    defer a.free(args);
    try std.testing.expectError(tool_schema.ValidationError.TooLong, tool_schema.validateArgs(owned.manifest.args, args));
}

test "manifest load + args schema validation (fs_read)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    var owned = try tool_manifest.loadManifest(a, "tests/fixtures/fs_read.toml");
    defer owned.deinit(a);

    try tool_schema.validateArgs(owned.manifest.args, "{\"path\":\"/workspace/README.md\",\"max_bytes\":65536}");
    try std.testing.expectError(tool_schema.ValidationError.MissingRequired, tool_schema.validateArgs(owned.manifest.args, "{\"max_bytes\":1}"));
    try std.testing.expectError(tool_schema.ValidationError.OutOfRange, tool_schema.validateArgs(owned.manifest.args, "{\"path\":\"/workspace/x\",\"max_bytes\":0}"));
}

const agent_prompt = @import("agent/prompt.zig");
const agent_bundle = @import("agent/bundle.zig");

test "system prompt uses stable workspace snapshot (fixture)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const vc = try config.loadAndValidate(a, "tests/fixture_prompt.toml");
    defer vc.deinit(a);

    const sys = try agent_prompt.buildSystemPrompt(a, vc);
    defer a.free(sys);

    const expected0 = try std.fs.cwd().readFileAlloc(a, "tests/golden/system_prompt_fixture.txt", 1024 * 1024);
    defer a.free(expected0);

    // substitute policy hash placeholder
    const placeholder = "__POLICY_HASH__";
    const idx = std.mem.indexOf(u8, expected0, placeholder) orelse return error.BadGolden;
    var expected = try a.alloc(u8, expected0.len - placeholder.len + vc.policy.policyHash().len);
    defer a.free(expected);

    std.mem.copyForwards(u8, expected[0..idx], expected0[0..idx]);
    std.mem.copyForwards(u8, expected[idx..][0..vc.policy.policyHash().len], vc.policy.policyHash());
    const tail_src = idx + placeholder.len;
    const tail_dst = idx + vc.policy.policyHash().len;
    std.mem.copyForwards(u8, expected[tail_dst..], expected0[tail_src..]);

    try std.testing.expectEqualStrings(expected, sys);
}

test "prompt bundle includes prompt_hash (fixture)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const vc = try config.loadAndValidate(a, "tests/fixture_prompt.toml");
    defer vc.deinit(a);

    var b = try agent_bundle.build(a, vc, "hello");
    defer b.deinit(a);

    try std.testing.expect(b.prompt_hash_hex.len == 64);
}

const providers = @import("providers/provider.zig");
const provider_factory = @import("providers/factory.zig");
const provider_fixtures = @import("providers/fixtures.zig");

test "provider fixtures record/replay (stub)" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    // Build a minimal config in-memory (avoid parsing); use stub provider
    var cfg = config.Config{};
    cfg.provider_primary.kind = .stub;
    cfg.provider_primary.model = "stub";
    cfg.provider_primary.temperature = 0.0;

    cfg.provider_fixtures.mode = .record;
    cfg.provider_fixtures.dir = "tests/.tmp_fixtures_record";

    cfg.provider_reliable.retries = 0;

    // Validate to get policy (workspace root doesn't matter for this test)
    const vc = try @import("config.zig").loadAndValidate(a, "zigclaw.toml");
    defer vc.deinit(a);

    // Overwrite provider configs in validated copy (policy stays same)
    var vc2 = vc; // copy
    vc2.raw.provider_primary = cfg.provider_primary;
    vc2.raw.provider_fixtures = cfg.provider_fixtures;
    vc2.raw.provider_reliable = cfg.provider_reliable;

    var p = try provider_factory.build(a, vc2);
    defer p.deinit(a);

    const req = providers.ChatRequest{
        .system = "sys",
        .user = "hello",
        .model = "stub",
        .temperature = 0.0,
        .memory_context = &.{},
    };

    const resp = try p.chat(a, req);
    defer a.free(resp.content);

    // fixture should exist
    const hash = try provider_fixtures.requestHashHexAlloc(a, req);
    defer a.free(hash);

    const path = try provider_fixtures.fixturePathAlloc(a, cfg.provider_fixtures.dir, hash);
    defer a.free(path);

    try std.testing.expect(std.fs.cwd().access(path, .{}) == null);

    // replay mode
    var cfg_r = cfg;
    cfg_r.provider_fixtures.mode = .replay;
    cfg_r.provider_fixtures.dir = cfg.provider_fixtures.dir;

    var vc3 = vc;
    vc3.raw.provider_primary = cfg_r.provider_primary;
    vc3.raw.provider_fixtures = cfg_r.provider_fixtures;
    vc3.raw.provider_reliable = cfg_r.provider_reliable;

    var pr = try provider_factory.build(a, vc3);
    defer pr.deinit(a);

    const resp2 = try pr.chat(a, req);
    defer a.free(resp2.content);

    try std.testing.expectEqualStrings(resp.content, resp2.content);

    // cleanup dir best-effort
    std.fs.cwd().deleteTree(cfg.provider_fixtures.dir) catch {};
}

const gw_http = @import("gateway/http.zig");

test "gateway http parses request line + headers" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const raw =
        "GET /health HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";

    // parseFromRaw is internal, so we call the public parse via readRequest by using a fixedBufferStream
    var fbs = std.io.fixedBufferStream(raw);
    var req = try gw_http.readRequest(a, fbs.reader(), 64 * 1024);
    defer req.deinit(a);

    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/health", req.target);
    try std.testing.expect(req.header("host") != null);
    try std.testing.expectEqual(@as(usize, 0), req.contentLength());
}

test "ToolRunResult toJsonAlloc includes request_id" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    var r = @import("tools/runner.zig").ToolRunResult{
        .request_id = try a.dupe(u8, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        .ok = true,
        .data_json = try a.dupe(u8, "{\"x\":1}"),
        .stdout = try a.dupe(u8, ""),
        .stderr = try a.dupe(u8, ""),
    };
    defer r.deinit(a);

    const json = try r.toJsonAlloc(a);
    defer a.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"request_id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") != null);
}
