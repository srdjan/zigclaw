const std = @import("std");
const log_reader = @import("log_reader.zig");
const verify_mod = @import("verify.zig");
const receipt_mod = @import("../attestation/receipt.zig");

pub const AuditReport = struct {
    request_id: ?[]const u8,
    events: []log_reader.DecisionEvent,
    verify_result: ?verify_mod.VerifyResult,
    from_ts: ?i64,
    to_ts: ?i64,

    pub fn deinit(self: *AuditReport, a: std.mem.Allocator) void {
        if (self.verify_result) |*vr| vr.deinit(a);
        log_reader.freeEvents(a, self.events);
    }
};

pub const SummaryStats = struct {
    total_events: usize,
    allowed_count: usize,
    denied_count: usize,
    unique_subjects: usize,
    unique_tools: usize,
    earliest_ts: ?i64,
    latest_ts: ?i64,
    subjects: [][]const u8,
    tools: [][]const u8,

    pub fn deinit(self: *SummaryStats, a: std.mem.Allocator) void {
        for (self.subjects) |s| a.free(s);
        a.free(self.subjects);
        for (self.tools) |t| a.free(t);
        a.free(self.tools);
    }
};

pub fn buildReport(
    a: std.mem.Allocator,
    io: std.Io,
    log_dir: []const u8,
    log_file: []const u8,
    workspace_root: []const u8,
    request_id: ?[]const u8,
    from_ts: ?i64,
    to_ts: ?i64,
) !AuditReport {
    const events = try log_reader.readEvents(a, io, log_dir, log_file, .{
        .from_ts = from_ts,
        .to_ts = to_ts,
        .request_id = request_id,
    });
    errdefer log_reader.freeEvents(a, events);

    // If a specific request_id is provided, attempt to verify its receipt
    var verify_result: ?verify_mod.VerifyResult = null;
    if (request_id) |rid| {
        const receipt_json = receipt_mod.readReceiptJsonAlloc(a, io, workspace_root, rid) catch null;
        if (receipt_json) |rj| {
            defer a.free(rj);
            verify_result = verify_mod.verifyAllEvents(a, rj) catch null;
        }
    }

    return .{
        .request_id = request_id,
        .events = events,
        .verify_result = verify_result,
        .from_ts = from_ts,
        .to_ts = to_ts,
    };
}

pub fn buildSummary(a: std.mem.Allocator, events: []const log_reader.DecisionEvent) !SummaryStats {
    var allowed: usize = 0;
    var denied: usize = 0;
    var earliest: ?i64 = null;
    var latest: ?i64 = null;

    var subject_set = std.StringHashMap(void).init(a);
    defer subject_set.deinit();
    var tool_set = std.StringHashMap(void).init(a);
    defer tool_set.deinit();

    for (events) |ev| {
        if (ev.allowed) {
            allowed += 1;
        } else {
            denied += 1;
        }
        if (earliest == null or ev.ts_unix_ms < earliest.?) earliest = ev.ts_unix_ms;
        if (latest == null or ev.ts_unix_ms > latest.?) latest = ev.ts_unix_ms;

        try subject_set.put(ev.subject, {});
        try tool_set.put(ev.decision, {});
    }

    // Collect unique subjects
    var subjects = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (subjects.items) |s| a.free(s);
        subjects.deinit();
    }
    var sit = subject_set.keyIterator();
    while (sit.next()) |k| try subjects.append(try a.dupe(u8, k.*));

    // Collect unique tools/decisions
    var tools = std.array_list.Managed([]const u8).init(a);
    errdefer {
        for (tools.items) |t| a.free(t);
        tools.deinit();
    }
    var tit = tool_set.keyIterator();
    while (tit.next()) |k| try tools.append(try a.dupe(u8, k.*));

    return .{
        .total_events = events.len,
        .allowed_count = allowed,
        .denied_count = denied,
        .unique_subjects = subject_set.count(),
        .unique_tools = tool_set.count(),
        .earliest_ts = earliest,
        .latest_ts = latest,
        .subjects = try subjects.toOwnedSlice(),
        .tools = try tools.toOwnedSlice(),
    };
}

pub fn formatText(a: std.mem.Allocator, report: AuditReport) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    const w = &aw.writer;

    try w.print("Audit Report", .{});
    if (report.request_id) |rid| {
        try w.print(" for request {s}", .{rid});
    }
    try w.print("\n", .{});

    try w.print("============================================================\n\n", .{});

    // Verification status
    if (report.verify_result) |vr| {
        try w.print("Merkle Verification: {s}\n", .{if (vr.overall_valid) "PASS" else "FAIL"});
        try w.print("  Root matches: {s}\n", .{if (vr.root_matches) "yes" else "no"});
        try w.print("  Expected root: {s}\n", .{vr.expected_root[0..]});
        try w.print("  Computed root: {s}\n", .{vr.computed_root[0..]});
        try w.print("  Events verified: {d}\n\n", .{vr.event_count});

        for (vr.event_statuses) |es| {
            try w.print("  Event {d}: {s} (hash: {s})\n", .{
                es.index,
                if (es.valid) "VALID" else "INVALID",
                es.leaf_hash[0..],
            });
        }
        try w.print("\n", .{});
    }

    // Decision events
    try w.print("Decision Events ({d} total)\n", .{report.events.len});
    for (report.events, 0..) |ev, i| {
        try w.print("\n  [{d}] ts={d} {s} subject={s} allowed={s}\n", .{
            i,
            ev.ts_unix_ms,
            ev.decision,
            ev.subject,
            if (ev.allowed) "true" else "false",
        });
        try w.print("      request={s} reason={s}\n", .{
            ev.request_id,
            ev.reason,
        });
    }

    return try aw.toOwnedSlice();
}

pub fn formatJson(a: std.mem.Allocator, report: AuditReport) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();

    if (report.request_id) |rid| {
        try stream.objectField("request_id");
        try stream.write(rid);
    }

    // Verification
    if (report.verify_result) |vr| {
        try stream.objectField("verification");
        try stream.beginObject();
        try stream.objectField("overall_valid");
        try stream.write(vr.overall_valid);
        try stream.objectField("root_matches");
        try stream.write(vr.root_matches);
        try stream.objectField("expected_root");
        try stream.write(vr.expected_root[0..]);
        try stream.objectField("computed_root");
        try stream.write(vr.computed_root[0..]);
        try stream.objectField("event_count");
        try stream.write(vr.event_count);
        try stream.objectField("events");
        try stream.beginArray();
        for (vr.event_statuses) |es| {
            try stream.beginObject();
            try stream.objectField("index");
            try stream.write(es.index);
            try stream.objectField("valid");
            try stream.write(es.valid);
            try stream.objectField("leaf_hash");
            try stream.write(es.leaf_hash[0..]);
            try stream.endObject();
        }
        try stream.endArray();
        try stream.endObject();
    }

    // Decision events
    try stream.objectField("events");
    try stream.beginArray();
    for (report.events) |ev| {
        try stream.beginObject();
        try stream.objectField("ts_unix_ms");
        try stream.write(ev.ts_unix_ms);
        try stream.objectField("request_id");
        try stream.write(ev.request_id);
        try stream.objectField("decision");
        try stream.write(ev.decision);
        try stream.objectField("subject");
        try stream.write(ev.subject);
        try stream.objectField("allowed");
        try stream.write(ev.allowed);
        try stream.objectField("reason");
        try stream.write(ev.reason);
        try stream.objectField("policy_hash");
        try stream.write(ev.policy_hash);
        try stream.endObject();
    }
    try stream.endArray();

    try stream.endObject();
    return try aw.toOwnedSlice();
}

pub fn formatSummaryText(a: std.mem.Allocator, stats: SummaryStats) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    const w = &aw.writer;

    try w.print("Audit Summary\n", .{});
    try w.print("=============\n\n", .{});
    try w.print("Total events: {d}\n", .{stats.total_events});
    try w.print("  Allowed: {d}\n", .{stats.allowed_count});
    try w.print("  Denied:  {d}\n", .{stats.denied_count});
    try w.print("Unique subjects: {d}\n", .{stats.unique_subjects});
    try w.print("Unique tools/decisions: {d}\n", .{stats.unique_tools});

    if (stats.earliest_ts) |ts| {
        try w.print("Time range: {d}", .{ts});
        if (stats.latest_ts) |lt| try w.print(" to {d}", .{lt});
        try w.print("\n", .{});
    }

    if (stats.subjects.len > 0) {
        try w.print("\nSubjects:\n", .{});
        for (stats.subjects) |s| try w.print("  - {s}\n", .{s});
    }

    if (stats.tools.len > 0) {
        try w.print("\nDecisions:\n", .{});
        for (stats.tools) |t| try w.print("  - {s}\n", .{t});
    }

    return try aw.toOwnedSlice();
}

pub fn formatSummaryJson(a: std.mem.Allocator, stats: SummaryStats) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("total_events");
    try stream.write(stats.total_events);
    try stream.objectField("allowed_count");
    try stream.write(stats.allowed_count);
    try stream.objectField("denied_count");
    try stream.write(stats.denied_count);
    try stream.objectField("unique_subjects");
    try stream.write(stats.unique_subjects);
    try stream.objectField("unique_tools");
    try stream.write(stats.unique_tools);
    try stream.objectField("earliest_ts");
    if (stats.earliest_ts) |ts| {
        try stream.write(ts);
    } else {
        try stream.write(null);
    }
    try stream.objectField("latest_ts");
    if (stats.latest_ts) |ts| {
        try stream.write(ts);
    } else {
        try stream.write(null);
    }

    try stream.objectField("subjects");
    try stream.beginArray();
    for (stats.subjects) |s| try stream.write(s);
    try stream.endArray();

    try stream.objectField("decisions");
    try stream.beginArray();
    for (stats.tools) |t| try stream.write(t);
    try stream.endArray();

    try stream.endObject();
    return try aw.toOwnedSlice();
}
