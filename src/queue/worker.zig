const std = @import("std");
const config = @import("../config.zig");
const loop = @import("../agent/loop.zig");
const obs = @import("../obs/logger.zig");
const trace = @import("../obs/trace.zig");
const tasks = @import("../primitives/tasks.zig");

pub const WorkerOptions = struct {
    once: bool = false,
    max_jobs: ?usize = null,
    poll_ms_override: ?u32 = null,
};

const QueueState = enum { queued, processing, completed, canceled, not_found };
const cancel_marker_suffix = ".cancel";
pub const RequestListFilter = enum { all, queued, processing, completed, canceled };

const JobKind = enum { agent };

const Job = struct {
    request_id: []u8,
    created_at_ms: i64,
    attempt: u32,
    max_retries: u32,
    kind: JobKind,
    agent_id: []u8,
    message: []u8,

    fn deinit(self: *Job, a: std.mem.Allocator) void {
        a.free(self.request_id);
        a.free(self.agent_id);
        a.free(self.message);
    }
};

pub fn enqueueAgent(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    message: []const u8,
    agent_id: ?[]const u8,
    request_id: ?[]const u8,
) ![]u8 {
    if (message.len == 0) return error.InvalidArgs;

    const resolved = try resolvePaths(a, cfg);
    defer resolved.deinit(a);
    try ensureDirs(io, resolved);

    const rid = if (request_id) |r|
        try a.dupe(u8, r)
    else
        try a.dupe(u8, trace.newRequestId(io).slice());
    errdefer a.free(rid);

    if (try requestIdExists(io, resolved, rid)) return error.DuplicateRequestId;

    var job = Job{
        .request_id = rid,
        .created_at_ms = nowMs(io),
        .attempt = 0,
        .max_retries = cfg.raw.queue.max_retries,
        .kind = .agent,
        .agent_id = if (agent_id) |id| try a.dupe(u8, id) else try a.dupe(u8, ""),
        .message = try a.dupe(u8, message),
    };
    defer a.free(job.agent_id);
    defer a.free(job.message);

    const payload = try encodeJob(a, job);
    defer a.free(payload);

    const name = try std.fmt.allocPrint(a, "{d}_{s}.json", .{ job.created_at_ms, job.request_id });
    defer a.free(name);
    const path = try std.fs.path.join(a, &.{ resolved.incoming, name });
    defer a.free(path);
    try writeFile(io, path, payload);

    return rid;
}

pub fn statusJsonAlloc(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    request_id: []const u8,
    include_payload: bool,
) ![]u8 {
    if (request_id.len == 0) return error.InvalidArgs;

    const resolved = try resolvePaths(a, cfg);
    defer resolved.deinit(a);
    try ensureDirs(io, resolved);

    var state: QueueState = .not_found;
    var selected_name: ?[]u8 = null;
    var selected_dir: ?[]const u8 = null;
    var cancel_pending = false;
    defer if (selected_name) |n| a.free(n);

    selected_name = try newestMatchingFileNameAlloc(a, io, resolved.outgoing, request_id);
    if (selected_name != null) {
        state = .completed;
        selected_dir = resolved.outgoing;
    } else {
        selected_name = try newestMatchingFileNameAlloc(a, io, resolved.processing, request_id);
        if (selected_name != null) {
            state = .processing;
            selected_dir = resolved.processing;
            const marker_path = try cancelMarkerPathAlloc(a, resolved, request_id);
            defer a.free(marker_path);
            cancel_pending = hasCancelMarkerAtPath(io, marker_path);
        } else {
            selected_name = try newestMatchingFileNameAlloc(a, io, resolved.incoming, request_id);
            if (selected_name != null) {
                state = .queued;
                selected_dir = resolved.incoming;
            } else {
                selected_name = try newestMatchingFileNameAlloc(a, io, resolved.canceled, request_id);
                if (selected_name != null) {
                    state = .canceled;
                    selected_dir = resolved.canceled;
                }
            }
        }
    }

    const payload = blk: {
        if (!include_payload) break :blk null;
        if (state != .completed) break :blk null;
        if (selected_name == null or selected_dir == null) break :blk null;
        const out_path = try std.fs.path.join(a, &.{ selected_dir.?, selected_name.? });
        defer a.free(out_path);
        break :blk try std.Io.Dir.cwd().readFileAlloc(io, out_path, a, std.Io.Limit.limited(1024 * 1024));
    };
    defer if (payload) |p| a.free(p);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("state");
    try stream.write(@tagName(state));
    try stream.objectField("found");
    try stream.write(state != .not_found);
    if (state == .processing) {
        try stream.objectField("cancel_pending");
        try stream.write(cancel_pending);
    }
    if (selected_name) |name| {
        try stream.objectField("file");
        try stream.write(name);
    }
    if (payload) |p| {
        const trimmed = std.mem.trimEnd(u8, p, "\r\n");
        var parsed_payload = std.json.parseFromSlice(std.json.Value, a, trimmed, .{}) catch {
            try stream.objectField("result_raw");
            try stream.write(trimmed);
            try stream.endObject();
            return try aw.toOwnedSlice();
        };
        defer parsed_payload.deinit();

        try stream.objectField("result");
        try stream.write(parsed_payload.value);
    }
    try stream.endObject();
    return try aw.toOwnedSlice();
}

pub fn cancelRequestJsonAlloc(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    request_id: []const u8,
) ![]u8 {
    if (request_id.len == 0) return error.InvalidArgs;

    const resolved = try resolvePaths(a, cfg);
    defer resolved.deinit(a);
    try ensureDirs(io, resolved);

    var state: QueueState = .not_found;
    var canceled = false;
    var moved: usize = 0;
    var already_canceled = false;
    var cancel_pending = false;

    if (try dirContainsRequest(io, resolved.outgoing, request_id)) {
        state = .completed;
    } else if (try dirContainsRequest(io, resolved.processing, request_id)) {
        const marker_path = try cancelMarkerPathAlloc(a, resolved, request_id);
        defer a.free(marker_path);
        const marker_existed = hasCancelMarkerAtPath(io, marker_path);
        if (!marker_existed) try writeCancelMarker(io, marker_path, request_id);

        state = .processing;
        canceled = true;
        cancel_pending = true;
        already_canceled = marker_existed;
    } else {
        moved = try moveMatchingFiles(a, io, resolved.incoming, resolved.canceled, request_id);
        if (moved > 0) {
            state = .canceled;
            canceled = true;
        } else if (try dirContainsRequest(io, resolved.canceled, request_id)) {
            state = .canceled;
            canceled = true;
            already_canceled = true;
        }
    }

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("state");
    try stream.write(@tagName(state));
    try stream.objectField("canceled");
    try stream.write(canceled);
    try stream.objectField("moved");
    try stream.write(moved);
    if (cancel_pending) {
        try stream.objectField("cancel_pending");
        try stream.write(true);
    }
    if (already_canceled) {
        try stream.objectField("already_canceled");
        try stream.write(true);
    }
    try stream.endObject();
    return try aw.toOwnedSlice();
}

const RequestListEntry = struct {
    request_id: []u8,
    file: []u8,
    state: QueueState,
    ts_ms: i64,
    due_ms: ?i64 = null,
    ready: ?bool = null,
    cancel_pending: bool = false,

    fn deinit(self: RequestListEntry, a: std.mem.Allocator) void {
        a.free(self.request_id);
        a.free(self.file);
    }
};

pub fn listRequestsJsonAlloc(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    limit: usize,
    filter: RequestListFilter,
) ![]u8 {
    const resolved = try resolvePaths(a, cfg);
    defer resolved.deinit(a);
    try ensureDirs(io, resolved);

    const now = nowMs(io);
    var entries = std.array_list.Managed(RequestListEntry).init(a);
    defer {
        for (entries.items) |it| it.deinit(a);
        entries.deinit();
    }

    try collectRequestEntries(a, io, resolved, resolved.incoming, .queued, now, &entries);
    try collectRequestEntries(a, io, resolved, resolved.processing, .processing, now, &entries);
    try collectRequestEntries(a, io, resolved, resolved.outgoing, .completed, now, &entries);
    try collectRequestEntries(a, io, resolved, resolved.canceled, .canceled, now, &entries);

    std.sort.block(RequestListEntry, entries.items, {}, struct {
        fn gt(_: void, lhs: RequestListEntry, rhs: RequestListEntry) bool {
            if (lhs.ts_ms != rhs.ts_ms) return lhs.ts_ms > rhs.ts_ms;
            return std.mem.order(u8, lhs.file, rhs.file) == .gt;
        }
    }.gt);

    var total: usize = 0;
    for (entries.items) |it| {
        if (requestListMatchesFilter(it.state, filter)) total += 1;
    }
    const capped = @min(limit, total);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("now_ms");
    try stream.write(now);
    try stream.objectField("filter");
    try stream.write(@tagName(filter));
    try stream.objectField("limit");
    try stream.write(limit);
    try stream.objectField("total");
    try stream.write(total);
    try stream.objectField("items");
    try stream.beginArray();
    var written: usize = 0;
    for (entries.items) |it| {
        if (!requestListMatchesFilter(it.state, filter)) continue;
        if (written >= capped) break;
        try stream.beginObject();
        try stream.objectField("request_id");
        try stream.write(it.request_id);
        try stream.objectField("state");
        try stream.write(@tagName(it.state));
        try stream.objectField("file");
        try stream.write(it.file);
        try stream.objectField("ts_ms");
        try stream.write(it.ts_ms);
        if (it.due_ms) |due_ms| {
            try stream.objectField("due_ms");
            try stream.write(due_ms);
        }
        if (it.ready) |ready| {
            try stream.objectField("ready");
            try stream.write(ready);
        }
        if (it.state == .processing) {
            try stream.objectField("cancel_pending");
            try stream.write(it.cancel_pending);
        }
        try stream.endObject();
        written += 1;
    }
    try stream.endArray();
    try stream.endObject();
    return try aw.toOwnedSlice();
}

pub fn runSummaryJsonAlloc(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    request_id: []const u8,
) ![]u8 {
    if (request_id.len == 0) return error.InvalidArgs;

    const status_json = try statusJsonAlloc(a, io, cfg, request_id, false);
    defer a.free(status_json);

    var status_parsed = try std.json.parseFromSlice(std.json.Value, a, status_json, .{});
    defer status_parsed.deinit();
    if (status_parsed.value != .object) return error.InvalidJson;
    const state_v = status_parsed.value.object.get("state") orelse return error.InvalidJson;
    if (state_v != .string) return error.InvalidJson;

    const receipt_path = try std.fmt.allocPrint(a, "{s}/.zigclaw/receipts/{s}.json", .{
        cfg.raw.security.workspace_root,
        request_id,
    });
    defer a.free(receipt_path);
    const capsule_path = try std.fmt.allocPrint(a, "{s}/.zigclaw/capsules/{s}.json", .{
        cfg.raw.security.workspace_root,
        request_id,
    });
    defer a.free(capsule_path);
    const status_path = try std.fmt.allocPrint(a, "/v1/requests/{s}", .{request_id});
    defer a.free(status_path);
    const receipt_url = try std.fmt.allocPrint(a, "/v1/receipts/{s}", .{request_id});
    defer a.free(receipt_url);
    const capsule_url = try std.fmt.allocPrint(a, "/v1/capsules/{s}", .{request_id});
    defer a.free(capsule_url);

    const receipt_exists = if (std.Io.Dir.cwd().statFile(io, receipt_path, .{})) |_| true else |_| false;
    const capsule_exists = if (std.Io.Dir.cwd().statFile(io, capsule_path, .{})) |_| true else |_| false;

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("state");
    try stream.write(state_v.string);
    try stream.objectField("status");
    try stream.write(status_parsed.value);
    try stream.objectField("status_path");
    try stream.write(status_path);
    try stream.objectField("receipt_path");
    try stream.write(receipt_path);
    try stream.objectField("receipt_exists");
    try stream.write(receipt_exists);
    try stream.objectField("receipt_url");
    try stream.write(receipt_url);
    try stream.objectField("capsule_path");
    try stream.write(capsule_path);
    try stream.objectField("capsule_exists");
    try stream.write(capsule_exists);
    try stream.objectField("capsule_url");
    try stream.write(capsule_url);
    try stream.endObject();
    return try aw.toOwnedSlice();
}

pub fn runWorker(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, opts: WorkerOptions) !void {
    const resolved = try resolvePaths(a, cfg);
    defer resolved.deinit(a);
    try ensureDirs(io, resolved);
    try recoverProcessing(a, io, resolved);

    const logger = obs.Logger.fromConfig(cfg, io);
    const poll_ms = opts.poll_ms_override orelse cfg.raw.queue.poll_ms;

    var handled: usize = 0;
    while (true) {
        const did = try processOne(a, io, cfg, resolved, logger);
        if (did) {
            handled += 1;
            if (opts.once) return;
            if (opts.max_jobs) |mx| {
                if (handled >= mx) return;
            }
            continue;
        }

        const picked = try maybePickupPrimitiveTask(a, io, cfg, logger);
        if (picked) continue;

        if (opts.once) return;
        io.sleep(std.Io.Duration.fromMilliseconds(@intCast(poll_ms)), .awake) catch {};
    }
}

const QueuePaths = struct {
    base: []u8,
    incoming: []u8,
    processing: []u8,
    outgoing: []u8,
    canceled: []u8,
    cancel_requests: []u8,

    fn deinit(self: QueuePaths, a: std.mem.Allocator) void {
        a.free(self.base);
        a.free(self.incoming);
        a.free(self.processing);
        a.free(self.outgoing);
        a.free(self.canceled);
        a.free(self.cancel_requests);
    }
};

fn resolvePaths(a: std.mem.Allocator, cfg: config.ValidatedConfig) !QueuePaths {
    const base = if (std.fs.path.isAbsolute(cfg.raw.queue.dir))
        try a.dupe(u8, cfg.raw.queue.dir)
    else
        try std.fs.path.join(a, &.{ cfg.raw.security.workspace_root, cfg.raw.queue.dir });
    errdefer a.free(base);

    const incoming = try std.fs.path.join(a, &.{ base, "incoming" });
    errdefer a.free(incoming);
    const processing = try std.fs.path.join(a, &.{ base, "processing" });
    errdefer a.free(processing);
    const outgoing = try std.fs.path.join(a, &.{ base, "outgoing" });
    errdefer a.free(outgoing);
    const canceled = try std.fs.path.join(a, &.{ base, "canceled" });
    errdefer a.free(canceled);
    const cancel_requests = try std.fs.path.join(a, &.{ base, "cancel_requests" });
    errdefer a.free(cancel_requests);

    return .{
        .base = base,
        .incoming = incoming,
        .processing = processing,
        .outgoing = outgoing,
        .canceled = canceled,
        .cancel_requests = cancel_requests,
    };
}

fn requestIdExists(io: std.Io, p: QueuePaths, request_id: []const u8) !bool {
    if (try dirContainsRequest(io, p.incoming, request_id)) return true;
    if (try dirContainsRequest(io, p.processing, request_id)) return true;
    if (try dirContainsRequest(io, p.outgoing, request_id)) return true;
    if (try dirContainsRequest(io, p.canceled, request_id)) return true;
    return false;
}

fn collectRequestEntries(
    a: std.mem.Allocator,
    io: std.Io,
    p: QueuePaths,
    dir_path: []const u8,
    state: QueueState,
    now_ms: i64,
    out: *std.array_list.Managed(RequestListEntry),
) !void {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return;
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!std.mem.endsWith(u8, ent.name, ".json")) continue;

        const rid = try requestIdFromFileNameAlloc(a, ent.name) orelse continue;
        errdefer a.free(rid);
        const file = try a.dupe(u8, ent.name);
        errdefer a.free(file);

        const ts = fileTimestampMs(ent.name) orelse now_ms;
        var item = RequestListEntry{
            .request_id = rid,
            .file = file,
            .state = state,
            .ts_ms = ts,
        };

        if (state == .queued) {
            item.due_ms = ts;
            item.ready = ts <= now_ms;
        } else if (state == .processing) {
            const marker_path = try cancelMarkerPathAlloc(a, p, rid);
            defer a.free(marker_path);
            item.cancel_pending = hasCancelMarkerAtPath(io, marker_path);
        }

        try out.append(item);
    }
}

fn requestIdFromFileNameAlloc(a: std.mem.Allocator, name: []const u8) !?[]u8 {
    if (!std.mem.endsWith(u8, name, ".json")) return null;
    const base = name[0 .. name.len - ".json".len];
    const sep = std.mem.indexOfScalar(u8, base, '_') orelse return null;
    if (sep + 1 >= base.len) return null;

    var rid_end = base.len;
    if (std.mem.lastIndexOf(u8, base, "_retry")) |retry_idx| {
        if (retry_idx > sep) {
            const suffix = base[retry_idx + "_retry".len ..];
            if (suffix.len > 0 and isAllDigits(suffix)) rid_end = retry_idx;
        }
    }
    if (rid_end <= sep + 1) return null;
    return try a.dupe(u8, base[sep + 1 .. rid_end]);
}

fn isAllDigits(s: []const u8) bool {
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn requestListMatchesFilter(state: QueueState, filter: RequestListFilter) bool {
    return switch (filter) {
        .all => state == .queued or state == .processing or state == .completed or state == .canceled,
        .queued => state == .queued,
        .processing => state == .processing,
        .completed => state == .completed,
        .canceled => state == .canceled,
    };
}

fn dirContainsRequest(io: std.Io, dir_path: []const u8, request_id: []const u8) !bool {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return false;
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (matchesRequestFileName(ent.name, request_id)) return true;
    }
    return false;
}

fn ensureDirs(io: std.Io, p: QueuePaths) !void {
    try std.Io.Dir.cwd().createDirPath(io, p.incoming);
    try std.Io.Dir.cwd().createDirPath(io, p.processing);
    try std.Io.Dir.cwd().createDirPath(io, p.outgoing);
    try std.Io.Dir.cwd().createDirPath(io, p.canceled);
    try std.Io.Dir.cwd().createDirPath(io, p.cancel_requests);
}

fn recoverProcessing(a: std.mem.Allocator, io: std.Io, p: QueuePaths) !void {
    var dir = std.Io.Dir.cwd().openDir(io, p.processing, .{}) catch return;
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!std.mem.endsWith(u8, ent.name, ".json")) continue;
        const from = try std.fs.path.join(a, &.{ p.processing, ent.name });
        defer a.free(from);
        const to = try std.fs.path.join(a, &.{ p.incoming, ent.name });
        defer a.free(to);
        std.Io.Dir.rename(std.Io.Dir.cwd(), from, std.Io.Dir.cwd(), to, io) catch {};
    }
}

fn processOne(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    p: QueuePaths,
    logger: obs.Logger,
) !bool {
    const name = try oldestIncomingNameAlloc(a, io, p.incoming);
    if (name == null) return false;
    defer a.free(name.?);

    if (fileTimestampMs(name.?)) |ts_ms| {
        if (ts_ms > nowMs(io)) return false;
    }

    const in_path = try std.fs.path.join(a, &.{ p.incoming, name.? });
    defer a.free(in_path);
    const proc_path = try std.fs.path.join(a, &.{ p.processing, name.? });
    defer a.free(proc_path);

    std.Io.Dir.rename(std.Io.Dir.cwd(), in_path, std.Io.Dir.cwd(), proc_path, io) catch return false;

    var job = decodeJobFromFile(a, io, proc_path, cfg.raw.queue.max_retries) catch |e| {
        const rid = trace.newRequestId(io);
        logger.logJson(a, .queue_job, rid.slice(), .{
            .status = "invalid_job",
            .error_name = @errorName(e),
            .file = name.?,
        });
        try writeOutcomeError(a, io, p.outgoing, rid.slice(), 0, "InvalidJob");
        _ = std.Io.Dir.cwd().deleteFile(io, proc_path) catch {};
        return true;
    };
    defer job.deinit(a);

    const marker_path = try cancelMarkerPathAlloc(a, p, job.request_id);
    defer a.free(marker_path);

    logger.logJson(a, .queue_job, job.request_id, .{
        .status = "start",
        .attempt = job.attempt,
        .kind = @tagName(job.kind),
    });

    if (job.kind != .agent) {
        try writeOutcomeError(a, io, p.outgoing, job.request_id, job.attempt, "UnsupportedJobKind");
        _ = std.Io.Dir.cwd().deleteFile(io, proc_path) catch {};
        logger.logJson(a, .queue_job, job.request_id, .{
            .status = "error",
            .attempt = job.attempt,
            .error_name = "UnsupportedJobKind",
        });
        return true;
    }

    if (hasCancelMarkerAtPath(io, marker_path)) {
        _ = try moveFileByName(a, io, p.processing, p.canceled, name.?);
        clearCancelMarker(io, marker_path);
        logger.logJson(a, .queue_job, job.request_id, .{
            .status = "canceled",
            .attempt = job.attempt,
            .reason = "marker_before_run",
        });
        return true;
    }

    var cancel_ctx = CancelCheckCtx{
        .io = io,
        .marker_path = marker_path,
    };

    const ro = loop.RunOptions{
        .agent_id = if (job.agent_id.len > 0) job.agent_id else null,
        .interactive = false,
        .cancel_check = .{
            .ctx = &cancel_ctx,
            .func = cancelCheckCallback,
        },
    };

    var res = loop.runLoop(a, io, cfg, job.message, job.request_id, ro) catch |e| {
        if (e == error.Canceled or hasCancelMarkerAtPath(io, marker_path)) {
            _ = try moveFileByName(a, io, p.processing, p.canceled, name.?);
            clearCancelMarker(io, marker_path);
            logger.logJson(a, .queue_job, job.request_id, .{
                .status = "canceled",
                .attempt = job.attempt,
                .reason = @errorName(e),
            });
            return true;
        }

        if (job.attempt < job.max_retries) {
            job.attempt += 1;
            const payload = try encodeJob(a, job);
            defer a.free(payload);

            const due_ms = computeRetryDueMs(io, cfg.raw.queue, job.request_id, job.attempt);

            const retry_name = try std.fmt.allocPrint(a, "{d}_{s}_retry{d}.json", .{
                due_ms,
                job.request_id,
                job.attempt,
            });
            defer a.free(retry_name);
            const retry_path = try std.fs.path.join(a, &.{ p.incoming, retry_name });
            defer a.free(retry_path);
            try writeFile(io, retry_path, payload);

            _ = std.Io.Dir.cwd().deleteFile(io, proc_path) catch {};

            logger.logJson(a, .queue_job, job.request_id, .{
                .status = "retry",
                .attempt = job.attempt,
                .error_name = @errorName(e),
                .next_due_ms = due_ms,
            });
            return true;
        }

        try writeOutcomeError(a, io, p.outgoing, job.request_id, job.attempt, @errorName(e));
        _ = std.Io.Dir.cwd().deleteFile(io, proc_path) catch {};
        logger.logJson(a, .queue_job, job.request_id, .{
            .status = "failed",
            .attempt = job.attempt,
            .error_name = @errorName(e),
        });
        return true;
    };
    defer res.deinit(a);

    try writeOutcomeOk(a, io, p.outgoing, job.request_id, job.attempt, res.turns, res.content);
    _ = std.Io.Dir.cwd().deleteFile(io, proc_path) catch {};
    clearCancelMarker(io, marker_path);

    logger.logJson(a, .queue_job, job.request_id, .{
        .status = "ok",
        .attempt = job.attempt,
        .turns = res.turns,
    });
    return true;
}

fn maybePickupPrimitiveTask(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    logger: obs.Logger,
) !bool {
    if (!cfg.raw.automation.task_pickup_enabled) return false;

    const owner = cfg.raw.automation.default_owner;
    var picked = try tasks.pickupNextTask(a, io, cfg, owner, cfg.raw.automation.pickup_statuses);
    if (picked == null) return false;
    defer picked.?.deinit(a);

    const rid = enqueueAgent(a, io, cfg, picked.?.message, null, null) catch |e| {
        logger.logJson(a, .queue_job, "task_pickup", .{
            .status = "enqueue_error",
            .task_slug = picked.?.slug,
            .error_name = @errorName(e),
        });
        return false;
    };
    defer a.free(rid);

    logger.logJson(a, .queue_job, rid, .{
        .status = "picked_from_primitive",
        .task_slug = picked.?.slug,
        .task_title = picked.?.title,
    });
    return true;
}

const CancelCheckCtx = struct {
    io: std.Io,
    marker_path: []const u8,
};

fn cancelCheckCallback(ctx: ?*anyopaque) anyerror!bool {
    const c = ctx orelse return false;
    const cc: *const CancelCheckCtx = @ptrCast(@alignCast(c));
    return hasCancelMarkerAtPath(cc.io, cc.marker_path);
}

fn oldestIncomingNameAlloc(a: std.mem.Allocator, io: std.Io, incoming_dir: []const u8) !?[]u8 {
    var dir = std.Io.Dir.cwd().openDir(io, incoming_dir, .{}) catch return null;
    defer dir.close(io);

    var it = dir.iterate();
    var best: ?[]u8 = null;

    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!std.mem.endsWith(u8, ent.name, ".json")) continue;

        if (best == null) {
            best = try a.dupe(u8, ent.name);
            continue;
        }

        if (std.mem.lessThan(u8, ent.name, best.?)) {
            a.free(best.?);
            best = try a.dupe(u8, ent.name);
        }
    }

    return best;
}

fn newestMatchingFileNameAlloc(a: std.mem.Allocator, io: std.Io, dir_path: []const u8, request_id: []const u8) !?[]u8 {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return null;
    defer dir.close(io);

    var it = dir.iterate();
    var best: ?[]u8 = null;
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!matchesRequestFileName(ent.name, request_id)) continue;

        if (best == null) {
            best = try a.dupe(u8, ent.name);
            continue;
        }
        if (std.mem.lessThan(u8, best.?, ent.name)) {
            a.free(best.?);
            best = try a.dupe(u8, ent.name);
        }
    }
    return best;
}

fn moveMatchingFiles(a: std.mem.Allocator, io: std.Io, src_dir: []const u8, dst_dir: []const u8, request_id: []const u8) !usize {
    var dir = std.Io.Dir.cwd().openDir(io, src_dir, .{}) catch return 0;
    defer dir.close(io);

    var moved: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!matchesRequestFileName(ent.name, request_id)) continue;

        const from = try std.fs.path.join(a, &.{ src_dir, ent.name });
        defer a.free(from);
        const to = try std.fs.path.join(a, &.{ dst_dir, ent.name });
        defer a.free(to);

        std.Io.Dir.rename(std.Io.Dir.cwd(), from, std.Io.Dir.cwd(), to, io) catch continue;
        moved += 1;
    }
    return moved;
}

fn fileTimestampMs(name: []const u8) ?i64 {
    const sep = std.mem.indexOfScalar(u8, name, '_') orelse return null;
    if (sep == 0) return null;
    return std.fmt.parseInt(i64, name[0..sep], 10) catch null;
}

fn computeRetryDueMs(io: std.Io, q: config.QueueConfig, request_id: []const u8, attempt: u32) i64 {
    const now = nowMs(io);
    if (q.retry_backoff_ms == 0) return now;

    const shift = @min(attempt -| 1, 31);
    const mul: u64 = @as(u64, 1) << @intCast(shift);
    const base_u64 = @as(u64, q.retry_backoff_ms) * mul;
    const base_i64: i64 = @intCast(@min(base_u64, @as(u64, @intCast(std.math.maxInt(i64)))));

    const jitter_pct = @min(q.retry_jitter_pct, 100);
    if (jitter_pct == 0 or base_i64 == 0) return now + base_i64;

    const mag_u64 = (@as(u64, @intCast(base_i64)) * @as(u64, jitter_pct)) / 100;
    if (mag_u64 == 0) return now + base_i64;

    const mag_i64: i64 = @intCast(@min(mag_u64, @as(u64, @intCast(std.math.maxInt(i64)))));
    const span_u64 = @as(u64, @intCast(mag_i64)) * 2 + 1;

    var hasher = std.hash.Wyhash.init(0x9e3779b97f4a7c15);
    hasher.update(request_id);
    hasher.update(std.mem.asBytes(&attempt));
    const r = hasher.final() % span_u64;
    const off = @as(i64, @intCast(r)) - mag_i64;

    const delay = @max(@as(i64, 0), base_i64 + off);
    return now + delay;
}

fn moveFileByName(a: std.mem.Allocator, io: std.Io, src_dir: []const u8, dst_dir: []const u8, name: []const u8) !bool {
    const from = try std.fs.path.join(a, &.{ src_dir, name });
    defer a.free(from);
    const to = try std.fs.path.join(a, &.{ dst_dir, name });
    defer a.free(to);

    std.Io.Dir.rename(std.Io.Dir.cwd(), from, std.Io.Dir.cwd(), to, io) catch return false;
    return true;
}

fn cancelMarkerPathAlloc(a: std.mem.Allocator, p: QueuePaths, request_id: []const u8) ![]u8 {
    const marker_name = try std.fmt.allocPrint(a, "{s}{s}", .{ request_id, cancel_marker_suffix });
    defer a.free(marker_name);
    return std.fs.path.join(a, &.{ p.cancel_requests, marker_name });
}

fn hasCancelMarkerAtPath(io: std.Io, marker_path: []const u8) bool {
    _ = std.Io.Dir.cwd().statFile(io, marker_path, .{}) catch return false;
    return true;
}

fn writeCancelMarker(io: std.Io, marker_path: []const u8, request_id: []const u8) !void {
    var f = try std.Io.Dir.cwd().createFile(io, marker_path, .{ .truncate = true });
    defer f.close(io);
    var buf: [256]u8 = undefined;
    var w = f.writer(io, &buf);
    try w.interface.writeAll(request_id);
    try w.interface.writeAll("\n");
    try w.flush();
}

fn clearCancelMarker(io: std.Io, marker_path: []const u8) void {
    _ = std.Io.Dir.cwd().deleteFile(io, marker_path) catch {};
}

pub fn metricsJsonAlloc(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig) ![]u8 {
    const resolved = try resolvePaths(a, cfg);
    defer resolved.deinit(a);
    try ensureDirs(io, resolved);

    const now = nowMs(io);
    const incoming = try countIncomingMetrics(io, resolved.incoming, now);
    const processing = try countJsonFiles(io, resolved.processing);
    const outgoing = try countJsonFiles(io, resolved.outgoing);
    const canceled = try countJsonFiles(io, resolved.canceled);
    const cancel_markers = try countAllFiles(io, resolved.cancel_requests);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("now_ms");
    try stream.write(now);
    try stream.objectField("incoming_total");
    try stream.write(incoming.total);
    try stream.objectField("incoming_ready");
    try stream.write(incoming.ready);
    try stream.objectField("incoming_delayed");
    try stream.write(incoming.delayed);
    if (incoming.next_due_ms) |v| {
        try stream.objectField("next_due_ms");
        try stream.write(v);
    }
    try stream.objectField("processing");
    try stream.write(processing);
    try stream.objectField("outgoing");
    try stream.write(outgoing);
    try stream.objectField("canceled");
    try stream.write(canceled);
    try stream.objectField("cancel_markers");
    try stream.write(cancel_markers);
    try stream.endObject();
    return try aw.toOwnedSlice();
}

const IncomingMetrics = struct {
    total: usize = 0,
    ready: usize = 0,
    delayed: usize = 0,
    next_due_ms: ?i64 = null,
};

fn countIncomingMetrics(io: std.Io, dir_path: []const u8, now_ms: i64) !IncomingMetrics {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return .{};
    defer dir.close(io);

    var out = IncomingMetrics{};
    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!std.mem.endsWith(u8, ent.name, ".json")) continue;
        out.total += 1;

        const ts = fileTimestampMs(ent.name);
        if (ts) |t| {
            if (t > now_ms) {
                out.delayed += 1;
                if (out.next_due_ms == null or t < out.next_due_ms.?) out.next_due_ms = t;
            } else {
                out.ready += 1;
            }
        } else {
            out.ready += 1;
        }
    }
    return out;
}

fn countJsonFiles(io: std.Io, dir_path: []const u8) !usize {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return 0;
    defer dir.close(io);

    var count: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!std.mem.endsWith(u8, ent.name, ".json")) continue;
        count += 1;
    }
    return count;
}

fn countAllFiles(io: std.Io, dir_path: []const u8) !usize {
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{}) catch return 0;
    defer dir.close(io);

    var count: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        count += 1;
    }
    return count;
}

fn matchesRequestFileName(name: []const u8, request_id: []const u8) bool {
    if (request_id.len == 0) return false;
    if (!std.mem.endsWith(u8, name, ".json")) return false;
    const ext_start = name.len - ".json".len;
    const base = name[0..ext_start];

    const idx = std.mem.indexOf(u8, base, request_id) orelse return false;
    if (idx == 0 or base[idx - 1] != '_') return false;

    const after = idx + request_id.len;
    if (after == base.len) return true;
    return base[after] == '_';
}

fn decodeJobFromFile(a: std.mem.Allocator, io: std.Io, path: []const u8, default_max_retries: u32) !Job {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(1024 * 1024));
    defer a.free(bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJobFormat;
    const obj = parsed.value.object;

    const kind_v = obj.get("kind") orelse return error.InvalidJobFormat;
    if (kind_v != .string) return error.InvalidJobFormat;
    if (!std.mem.eql(u8, kind_v.string, "agent")) return error.UnsupportedJobKind;

    const agent_v = obj.get("agent") orelse return error.InvalidJobFormat;
    if (agent_v != .object) return error.InvalidJobFormat;
    const agent_obj = agent_v.object;

    const msg_v = agent_obj.get("message") orelse return error.InvalidJobFormat;
    if (msg_v != .string or msg_v.string.len == 0) return error.InvalidJobFormat;

    const agent_id: []const u8 = if (agent_obj.get("agent_id")) |aid| switch (aid) {
        .string => |s| s,
        else => return error.InvalidJobFormat,
    } else "";

    const rid: []const u8 = if (obj.get("request_id")) |rv| switch (rv) {
        .string => |s| s,
        else => return error.InvalidJobFormat,
    } else trace.newRequestId(io).slice();

    const created_at_ms: i64 = if (obj.get("created_at_ms")) |tv| switch (tv) {
        .integer => |i| i,
        else => return error.InvalidJobFormat,
    } else nowMs(io);

    const attempt: u32 = if (obj.get("attempt")) |av| switch (av) {
        .integer => |i| std.math.cast(u32, i) orelse return error.InvalidJobFormat,
        else => return error.InvalidJobFormat,
    } else 0;

    const max_retries: u32 = if (obj.get("max_retries")) |mv| switch (mv) {
        .integer => |i| std.math.cast(u32, i) orelse return error.InvalidJobFormat,
        else => return error.InvalidJobFormat,
    } else default_max_retries;

    return .{
        .request_id = try a.dupe(u8, rid),
        .created_at_ms = created_at_ms,
        .attempt = attempt,
        .max_retries = max_retries,
        .kind = .agent,
        .agent_id = try a.dupe(u8, agent_id),
        .message = try a.dupe(u8, msg_v.string),
    };
}

fn encodeJob(a: std.mem.Allocator, job: Job) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(job.request_id);
    try stream.objectField("created_at_ms");
    try stream.write(job.created_at_ms);
    try stream.objectField("attempt");
    try stream.write(job.attempt);
    try stream.objectField("max_retries");
    try stream.write(job.max_retries);
    try stream.objectField("kind");
    try stream.write(@tagName(job.kind));

    try stream.objectField("agent");
    try stream.beginObject();
    try stream.objectField("message");
    try stream.write(job.message);
    if (job.agent_id.len > 0) {
        try stream.objectField("agent_id");
        try stream.write(job.agent_id);
    }
    try stream.endObject();
    try stream.endObject();
    return try aw.toOwnedSlice();
}

fn writeOutcomeOk(
    a: std.mem.Allocator,
    io: std.Io,
    outgoing_dir: []const u8,
    request_id: []const u8,
    attempt: u32,
    turns: usize,
    content: []const u8,
) !void {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("ok");
    try stream.write(true);
    try stream.objectField("kind");
    try stream.write("agent");
    try stream.objectField("attempt");
    try stream.write(attempt);
    try stream.objectField("turns");
    try stream.write(turns);
    try stream.objectField("content");
    try stream.write(content);
    try stream.endObject();

    const payload = try aw.toOwnedSlice();
    defer a.free(payload);
    try writeOutcomeFile(a, io, outgoing_dir, request_id, payload);
}

fn writeOutcomeError(
    a: std.mem.Allocator,
    io: std.Io,
    outgoing_dir: []const u8,
    request_id: []const u8,
    attempt: u32,
    err_name: []const u8,
) !void {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("request_id");
    try stream.write(request_id);
    try stream.objectField("ok");
    try stream.write(false);
    try stream.objectField("kind");
    try stream.write("agent");
    try stream.objectField("attempt");
    try stream.write(attempt);
    try stream.objectField("error");
    try stream.write(err_name);
    try stream.endObject();
    const payload = try aw.toOwnedSlice();
    defer a.free(payload);
    try writeOutcomeFile(a, io, outgoing_dir, request_id, payload);
}

fn writeOutcomeFile(a: std.mem.Allocator, io: std.Io, outgoing_dir: []const u8, request_id: []const u8, payload: []const u8) !void {
    const name = try std.fmt.allocPrint(a, "{d}_{s}.json", .{ nowMs(io), request_id });
    defer a.free(name);
    const path = try std.fs.path.join(a, &.{ outgoing_dir, name });
    defer a.free(path);
    try writeFile(io, path, payload);
}

fn writeFile(io: std.Io, path: []const u8, bytes: []const u8) !void {
    var f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var w = f.writer(io, &buf);
    try w.interface.writeAll(bytes);
    try w.interface.writeAll("\n");
    try w.flush();
}

fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Clock.now(.real, io);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}
