const std = @import("std");
const config = @import("../config.zig");

pub const FrontmatterValue = union(enum) {
    string: []u8,
    boolean: bool,
    list: [][]u8,

    fn deinit(self: *FrontmatterValue, a: std.mem.Allocator) void {
        switch (self.*) {
            .string => |s| a.free(s),
            .list => |items| {
                for (items) |it| a.free(it);
                a.free(items);
            },
            .boolean => {},
        }
    }
};

const Frontmatter = struct {
    map: std.StringHashMap(FrontmatterValue),

    fn init(a: std.mem.Allocator) Frontmatter {
        return .{ .map = std.StringHashMap(FrontmatterValue).init(a) };
    }

    fn deinit(self: *Frontmatter, a: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |e| {
            a.free(e.key_ptr.*);
            e.value_ptr.deinit(a);
        }
        self.map.deinit();
    }

    fn put(self: *Frontmatter, a: std.mem.Allocator, key: []const u8, value: FrontmatterValue) !void {
        if (self.map.getEntry(key)) |entry| {
            entry.value_ptr.deinit(a);
            entry.value_ptr.* = value;
            return;
        }
        try self.map.put(try a.dupe(u8, key), value);
    }

    fn setStringDup(self: *Frontmatter, a: std.mem.Allocator, key: []const u8, value: []const u8) !void {
        try self.put(a, key, .{ .string = try a.dupe(u8, value) });
    }

    fn setBool(self: *Frontmatter, a: std.mem.Allocator, key: []const u8, value: bool) !void {
        try self.put(a, key, .{ .boolean = value });
    }

    fn setListDup(self: *Frontmatter, a: std.mem.Allocator, key: []const u8, values: []const []const u8) !void {
        var out = std.array_list.Managed([]u8).init(a);
        defer out.deinit();

        for (values) |v| try out.append(try a.dupe(u8, v));

        try self.put(a, key, .{ .list = try out.toOwnedSlice() });
    }

    fn get(self: *const Frontmatter, key: []const u8) ?FrontmatterValue {
        return self.map.get(key);
    }

    fn getString(self: *const Frontmatter, key: []const u8) ?[]const u8 {
        const v = self.map.get(key) orelse return null;
        return switch (v) {
            .string => |s| s,
            else => null,
        };
    }

    fn has(self: *const Frontmatter, key: []const u8) bool {
        return self.map.get(key) != null;
    }
};

const ParsedDoc = struct {
    fm: Frontmatter,
    body: []u8,

    fn deinit(self: *ParsedDoc, a: std.mem.Allocator) void {
        self.fm.deinit(a);
        a.free(self.body);
    }
};

pub const TaskSummary = struct {
    slug: []u8,
    title: []u8,
    status: []u8,
    priority: ?[]u8,
    owner: ?[]u8,
    project: ?[]u8,
    path: []u8,

    pub fn deinit(self: *TaskSummary, a: std.mem.Allocator) void {
        a.free(self.slug);
        a.free(self.title);
        a.free(self.status);
        if (self.priority) |v| a.free(v);
        if (self.owner) |v| a.free(v);
        if (self.project) |v| a.free(v);
        a.free(self.path);
    }
};

pub fn freeTaskSummaries(a: std.mem.Allocator, items: []TaskSummary) void {
    for (items) |*item| item.deinit(a);
    a.free(items);
}

pub const AddOptions = struct {
    title: []const u8,
    status: ?[]const u8 = null,
    priority: ?[]const u8 = null,
    owner: ?[]const u8 = null,
    project: ?[]const u8 = null,
    tags: ?[]const u8 = null,
    due: ?[]const u8 = null,
    estimate: ?[]const u8 = null,
    parent: ?[]const u8 = null,
    depends_on: ?[]const u8 = null,
    body: ?[]const u8 = null,
    event_id: ?[]const u8 = null,
};

pub const AddResult = struct {
    slug: []u8,
    path: []u8,
    created: bool,

    pub fn deinit(self: *AddResult, a: std.mem.Allocator) void {
        a.free(self.slug);
        a.free(self.path);
    }
};

pub const PickedTask = struct {
    slug: []u8,
    title: []u8,
    message: []u8,

    pub fn deinit(self: *PickedTask, a: std.mem.Allocator) void {
        a.free(self.slug);
        a.free(self.title);
        a.free(self.message);
    }
};

pub const ListOptions = struct {
    status: ?[]const u8 = null,
    owner: ?[]const u8 = null,
    project: ?[]const u8 = null,
};

pub const FieldType = enum { string, date, string_array, boolean };

pub const FieldDef = struct {
    name: []u8,
    typ: FieldType = .string,
    required: bool = false,
    default_string: ?[]u8 = null,
    enum_values: [][]u8 = &.{},

    fn deinit(self: *FieldDef, a: std.mem.Allocator) void {
        a.free(self.name);
        if (self.default_string) |s| a.free(s);
        for (self.enum_values) |ev| a.free(ev);
        if (self.enum_values.len > 0) a.free(self.enum_values);
    }
};

pub const TaskTemplate = struct {
    fields: []FieldDef,

    pub fn deinit(self: *TaskTemplate, a: std.mem.Allocator) void {
        for (self.fields) |*f| f.deinit(a);
        a.free(self.fields);
    }

    fn get(self: *const TaskTemplate, key: []const u8) ?FieldDef {
        for (self.fields) |f| {
            if (std.mem.eql(u8, f.name, key)) return f;
        }
        return null;
    }
};

pub fn addTask(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, opts: AddOptions) !AddResult {
    if (opts.title.len == 0) return error.InvalidArgs;

    const memory_root = try resolveMemoryRootAlloc(a, cfg);
    defer a.free(memory_root);
    const templates_dir = try resolveTemplatesDirAlloc(a, cfg);
    defer a.free(templates_dir);
    const tasks_dir = try std.fs.path.join(a, &.{ memory_root, "tasks" });
    defer a.free(tasks_dir);

    try ensurePrimitiveDirs(io, memory_root, templates_dir);

    if (opts.event_id) |event_id| {
        if (try findTaskSlugByEventIdAlloc(a, io, tasks_dir, event_id)) |existing_slug| {
            const existing_path = try std.fs.path.join(a, &.{ tasks_dir, existing_slug });
            return .{ .slug = existing_slug, .path = existing_path, .created = false };
        }
    }

    var template = try loadTaskTemplate(a, io, cfg);
    defer template.deinit(a);

    var fm = Frontmatter.init(a);
    defer fm.deinit(a);

    const now_ms = nowUnixMs(io);
    const now_s = try std.fmt.allocPrint(a, "{d}", .{now_ms});
    defer a.free(now_s);

    try fm.setStringDup(a, "title", opts.title);
    try fm.setStringDup(a, "status", opts.status orelse "open");
    try fm.setStringDup(a, "created_at", now_s);
    try fm.setStringDup(a, "updated_at", now_s);

    if (opts.priority) |v| try fm.setStringDup(a, "priority", v);
    if (opts.owner) |v| try fm.setStringDup(a, "owner", v);
    if (opts.project) |v| try fm.setStringDup(a, "project", v);
    if (opts.due) |v| try fm.setStringDup(a, "due", v);
    if (opts.estimate) |v| try fm.setStringDup(a, "estimate", v);
    if (opts.parent) |v| try fm.setStringDup(a, "parent", v);
    if (opts.event_id) |v| try fm.setStringDup(a, "event_id", v);

    if (opts.tags) |raw| {
        const list = try parseCommaListAlloc(a, raw);
        defer freeStringList(a, list);
        try fm.setListDup(a, "tags", list);
    }
    if (opts.depends_on) |raw| {
        const list = try parseCommaListAlloc(a, raw);
        defer freeStringList(a, list);
        try fm.setListDup(a, "depends_on", list);
    }

    try applyTaskTemplateDefaultsAndValidate(a, &fm, template);

    const base_slug = try slugifyAlloc(a, opts.title);
    defer a.free(base_slug);

    const filename = try nextTaskFileNameAlloc(a, io, tasks_dir, base_slug);
    defer a.free(filename);

    const out_path = try std.fs.path.join(a, &.{ tasks_dir, filename });

    const body = if (opts.body) |b| b else "";
    const rendered = try renderTaskDocAlloc(a, fm, body);
    defer a.free(rendered);
    try writeFile(io, out_path, rendered);

    const stem = fileStem(filename);
    return .{
        .slug = try a.dupe(u8, stem),
        .path = out_path,
        .created = true,
    };
}

pub fn listTasks(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, opts: ListOptions) ![]TaskSummary {
    const memory_root = try resolveMemoryRootAlloc(a, cfg);
    defer a.free(memory_root);

    const tasks_dir = try std.fs.path.join(a, &.{ memory_root, "tasks" });
    defer a.free(tasks_dir);

    var dir = std.Io.Dir.cwd().openDir(io, tasks_dir, .{}) catch return try a.dupe(TaskSummary, &.{});
    defer dir.close(io);

    var items = std.array_list.Managed(TaskSummary).init(a);
    errdefer {
        for (items.items) |*item| item.deinit(a);
        items.deinit();
    }

    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file) continue;
        if (!std.mem.endsWith(u8, ent.name, ".md")) continue;

        const path = try std.fs.path.join(a, &.{ tasks_dir, ent.name });
        defer a.free(path);

        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(512 * 1024)) catch continue;
        defer a.free(bytes);

        var doc = parseDocAlloc(a, bytes) catch continue;
        defer doc.deinit(a);

        const title = doc.fm.getString("title") orelse continue;
        const status = doc.fm.getString("status") orelse "open";
        const owner = doc.fm.getString("owner");
        const project = doc.fm.getString("project");

        if (opts.status) |want| {
            if (!std.mem.eql(u8, want, status)) continue;
        }
        if (opts.owner) |want| {
            if (owner == null or !std.mem.eql(u8, want, owner.?)) continue;
        }
        if (opts.project) |want| {
            if (project == null or !std.mem.eql(u8, want, project.?)) continue;
        }

        const slug = fileStem(ent.name);

        try items.append(.{
            .slug = try a.dupe(u8, slug),
            .title = try a.dupe(u8, title),
            .status = try a.dupe(u8, status),
            .priority = if (doc.fm.getString("priority")) |v| try a.dupe(u8, v) else null,
            .owner = if (owner) |v| try a.dupe(u8, v) else null,
            .project = if (project) |v| try a.dupe(u8, v) else null,
            .path = try a.dupe(u8, path),
        });
    }

    std.sort.block(TaskSummary, items.items, {}, struct {
        fn lt(_: void, a_: TaskSummary, b_: TaskSummary) bool {
            return std.mem.lessThan(u8, a_.slug, b_.slug);
        }
    }.lt);

    return try items.toOwnedSlice();
}

pub fn markTaskDone(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, slug: []const u8, reason: ?[]const u8) !TaskSummary {
    try setTaskStatus(a, io, cfg, slug, "done", reason, null);

    const listed = try listTasks(a, io, cfg, .{});
    defer freeTaskSummaries(a, listed);
    for (listed) |item| {
        if (std.mem.eql(u8, item.slug, slug)) {
            return .{
                .slug = try a.dupe(u8, item.slug),
                .title = try a.dupe(u8, item.title),
                .status = try a.dupe(u8, item.status),
                .priority = if (item.priority) |v| try a.dupe(u8, v) else null,
                .owner = if (item.owner) |v| try a.dupe(u8, v) else null,
                .project = if (item.project) |v| try a.dupe(u8, v) else null,
                .path = try a.dupe(u8, item.path),
            };
        }
    }
    return error.TaskNotFound;
}

pub fn setTaskStatus(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    slug: []const u8,
    new_status: []const u8,
    reason: ?[]const u8,
    owner_override: ?[]const u8,
) !void {
    const memory_root = try resolveMemoryRootAlloc(a, cfg);
    defer a.free(memory_root);
    const tasks_dir = try std.fs.path.join(a, &.{ memory_root, "tasks" });
    defer a.free(tasks_dir);

    const filename = if (std.mem.endsWith(u8, slug, ".md"))
        try a.dupe(u8, slug)
    else
        try std.fmt.allocPrint(a, "{s}.md", .{slug});
    defer a.free(filename);

    const path = try std.fs.path.join(a, &.{ tasks_dir, filename });
    defer a.free(path);

    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(512 * 1024)) catch return error.TaskNotFound;
    defer a.free(bytes);

    var doc = try parseDocAlloc(a, bytes);
    defer doc.deinit(a);

    const prev_status = doc.fm.getString("status") orelse "open";

    try doc.fm.setStringDup(a, "status", new_status);
    if (owner_override) |owner| {
        try doc.fm.setStringDup(a, "owner", owner);
    }

    const now_s = try std.fmt.allocPrint(a, "{d}", .{nowUnixMs(io)});
    defer a.free(now_s);
    try doc.fm.setStringDup(a, "updated_at", now_s);

    const body = try appendTransitionLedgerAlloc(a, doc.body, prev_status, new_status, reason, now_s);
    defer a.free(body);

    const rendered = try renderTaskDocAlloc(a, doc.fm, body);
    defer a.free(rendered);
    try writeFile(io, path, rendered);
}

pub fn pickupNextTask(
    a: std.mem.Allocator,
    io: std.Io,
    cfg: config.ValidatedConfig,
    owner: []const u8,
    pickup_statuses: []const []const u8,
) !?PickedTask {
    const tasks = try listTasks(a, io, cfg, .{});
    defer freeTaskSummaries(a, tasks);

    var selected_exact: ?TaskSummary = null;
    var selected_unowned: ?TaskSummary = null;

    for (tasks) |item| {
        if (!statusAllowed(item.status, pickup_statuses)) continue;
        if (item.owner) |it_owner| {
            if (owner.len > 0 and std.mem.eql(u8, it_owner, owner)) {
                selected_exact = item;
                break;
            }
        } else if (selected_unowned == null) {
            selected_unowned = item;
        }
    }

    const chosen = if (selected_exact) |v| v else if (selected_unowned) |v| v else return null;

    const assign_owner = if (chosen.owner == null and owner.len > 0) owner else null;

    try setTaskStatus(a, io, cfg, chosen.slug, "in-progress", "picked by queue heartbeat", assign_owner);

    const message = try std.fmt.allocPrint(
        a,
        "Work task '{s}' (slug: {s}) from memory/tasks/{s}.md. Use memory context and mark it done when complete.",
        .{ chosen.title, chosen.slug, chosen.slug },
    );

    return .{
        .slug = try a.dupe(u8, chosen.slug),
        .title = try a.dupe(u8, chosen.title),
        .message = message,
    };
}

pub fn pickupNextOpenTask(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, owner: []const u8) !?PickedTask {
    return try pickupNextTask(a, io, cfg, owner, &.{"open"});
}

pub fn listJsonAlloc(a: std.mem.Allocator, items: []const TaskSummary) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("tasks");
    try stream.beginArray();
    for (items) |item| {
        try stream.beginObject();
        try stream.objectField("slug");
        try stream.write(item.slug);
        try stream.objectField("title");
        try stream.write(item.title);
        try stream.objectField("status");
        try stream.write(item.status);
        if (item.priority) |v| {
            try stream.objectField("priority");
            try stream.write(v);
        }
        if (item.owner) |v| {
            try stream.objectField("owner");
            try stream.write(v);
        }
        if (item.project) |v| {
            try stream.objectField("project");
            try stream.write(v);
        }
        try stream.objectField("path");
        try stream.write(item.path);
        try stream.endObject();
    }
    try stream.endArray();
    try stream.endObject();

    return try aw.toOwnedSlice();
}

pub fn summaryJsonAlloc(a: std.mem.Allocator, item: TaskSummary) ![]u8 {
    return try listJsonAlloc(a, &.{item});
}

pub fn validateTaskPrimitive(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, target: []const u8) !void {
    const memory_root = try resolveMemoryRootAlloc(a, cfg);
    defer a.free(memory_root);

    const tasks_dir = try std.fs.path.join(a, &.{ memory_root, "tasks" });
    defer a.free(tasks_dir);

    const path = blk: {
        if (std.mem.indexOfScalar(u8, target, '/') != null or std.mem.endsWith(u8, target, ".md")) {
            break :blk try a.dupe(u8, target);
        }
        const fnm = try std.fmt.allocPrint(a, "{s}.md", .{target});
        defer a.free(fnm);
        break :blk try std.fs.path.join(a, &.{ tasks_dir, fnm });
    };
    defer a.free(path);

    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(512 * 1024));
    defer a.free(bytes);

    var doc = try parseDocAlloc(a, bytes);
    defer doc.deinit(a);

    var template = try loadTaskTemplate(a, io, cfg);
    defer template.deinit(a);
    try applyTaskTemplateDefaultsAndValidate(a, &doc.fm, template);
}

pub fn listTemplatesJsonAlloc(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig) ![]u8 {
    const templates_dir = try resolveTemplatesDirAlloc(a, cfg);
    defer a.free(templates_dir);

    var names = std.array_list.Managed([]u8).init(a);
    defer {
        for (names.items) |n| a.free(n);
        names.deinit();
    }

    var dir = std.Io.Dir.cwd().openDir(io, templates_dir, .{}) catch |e| switch (e) {
        error.FileNotFound => null,
        else => return e,
    };
    defer if (dir) |*d| d.close(io);

    if (dir) |*d| {
        var it = d.iterate();
        while (try it.next(io)) |ent| {
            if (ent.kind != .file) continue;
            if (!std.mem.endsWith(u8, ent.name, ".md")) continue;
            const stem = fileStem(ent.name);
            try names.append(try a.dupe(u8, stem));
        }
    }

    var has_task = false;
    for (names.items) |name| {
        if (std.mem.eql(u8, name, "task")) {
            has_task = true;
            break;
        }
    }
    if (!has_task) try names.append(try a.dupe(u8, "task"));

    std.sort.block([]u8, names.items, {}, struct {
        fn lt(_: void, a_: []u8, b_: []u8) bool {
            return std.mem.lessThan(u8, a_, b_);
        }
    }.lt);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    try stream.objectField("templates");
    try stream.beginArray();
    for (names.items) |n| try stream.write(n);
    try stream.endArray();
    try stream.endObject();

    return try aw.toOwnedSlice();
}

pub fn showTemplateAlloc(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, name: []const u8) ![]u8 {
    const templates_dir = try resolveTemplatesDirAlloc(a, cfg);
    defer a.free(templates_dir);

    const path = try std.fs.path.join(a, &.{ templates_dir, name });
    defer a.free(path);

    const full = if (std.mem.endsWith(u8, name, ".md"))
        try a.dupe(u8, path)
    else
        try std.fmt.allocPrint(a, "{s}.md", .{path});
    defer a.free(full);

    const bytes = std.Io.Dir.cwd().readFileAlloc(io, full, a, std.Io.Limit.limited(256 * 1024)) catch |e| switch (e) {
        error.FileNotFound => {
            if (std.mem.eql(u8, name, "task") or std.mem.eql(u8, name, "task.md")) {
                return try a.dupe(u8, default_task_template_md);
            }
            return e;
        },
        else => return e,
    };
    return bytes;
}

pub fn validateTemplate(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig, name: []const u8) !void {
    const content = try showTemplateAlloc(a, io, cfg, name);
    defer a.free(content);

    if (!(std.mem.eql(u8, name, "task") or std.mem.eql(u8, name, "task.md"))) return;

    var template = try parseTaskTemplateAlloc(a, content);
    defer template.deinit(a);
}

pub fn ensureDefaultTemplateIfMissing(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig) !void {
    const templates_dir = try resolveTemplatesDirAlloc(a, cfg);
    defer a.free(templates_dir);

    try std.Io.Dir.cwd().createDirPath(io, templates_dir);

    const path = try std.fs.path.join(a, &.{ templates_dir, "task.md" });
    defer a.free(path);

    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch {
        try writeFile(io, path, default_task_template_md);
        return;
    };
}

fn loadTaskTemplate(a: std.mem.Allocator, io: std.Io, cfg: config.ValidatedConfig) !TaskTemplate {
    const tpl = showTemplateAlloc(a, io, cfg, "task") catch |e| switch (e) {
        error.FileNotFound => return defaultTaskTemplate(a),
        else => return e,
    };
    defer a.free(tpl);

    return parseTaskTemplateAlloc(a, tpl) catch defaultTaskTemplate(a);
}

fn parseTaskTemplateAlloc(a: std.mem.Allocator, content: []const u8) !TaskTemplate {
    var yaml = content;
    if (std.mem.startsWith(u8, content, "---")) {
        const maybe = extractFrontmatterSlice(content);
        if (maybe) |fm_slice| yaml = fm_slice;
    }

    var fields = std.array_list.Managed(FieldDef).init(a);
    errdefer {
        for (fields.items) |*f| f.deinit(a);
        fields.deinit();
    }

    var primitive_ok = false;
    var in_fields = false;
    var current: ?usize = null;

    var it = std.mem.splitScalar(u8, yaml, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) continue;

        const indent = countLeadingSpaces(line);
        const t = line[indent..];

        if (indent == 0) {
            if (std.mem.startsWith(u8, t, "primitive:")) {
                const val = trimYamlScalar(t["primitive:".len..]);
                primitive_ok = std.mem.eql(u8, val, "task");
                continue;
            }
            if (std.mem.eql(u8, t, "fields:")) {
                in_fields = true;
                continue;
            }
            continue;
        }

        if (!in_fields) continue;

        if (indent == 2 and t[t.len - 1] == ':') {
            const name = std.mem.trim(u8, t[0 .. t.len - 1], " ");
            try fields.append(.{ .name = try a.dupe(u8, name) });
            current = fields.items.len - 1;
            continue;
        }

        if (indent == 4 and current != null) {
            const sep = std.mem.indexOfScalar(u8, t, ':') orelse continue;
            const key = std.mem.trim(u8, t[0..sep], " ");
            const val = std.mem.trim(u8, t[sep + 1 ..], " ");

            const f = &fields.items[current.?];
            if (std.mem.eql(u8, key, "type")) {
                const ty = trimYamlScalar(val);
                if (std.mem.eql(u8, ty, "string")) f.typ = .string else if (std.mem.eql(u8, ty, "date")) f.typ = .date else if (std.mem.eql(u8, ty, "string[]")) f.typ = .string_array else if (std.mem.eql(u8, ty, "boolean")) f.typ = .boolean else return error.InvalidTemplate;
                continue;
            }
            if (std.mem.eql(u8, key, "required")) {
                const b = trimYamlScalar(val);
                f.required = std.mem.eql(u8, b, "true");
                continue;
            }
            if (std.mem.eql(u8, key, "default")) {
                if (f.default_string) |old| a.free(old);
                f.default_string = try a.dupe(u8, trimYamlScalar(val));
                continue;
            }
            if (std.mem.eql(u8, key, "enum")) {
                for (f.enum_values) |ev| a.free(ev);
                if (f.enum_values.len > 0) a.free(f.enum_values);
                f.enum_values = try parseYamlArrayAlloc(a, val);
                continue;
            }
        }
    }

    if (!primitive_ok) return error.InvalidTemplate;
    if (fields.items.len == 0) return error.InvalidTemplate;

    return .{ .fields = try fields.toOwnedSlice() };
}

fn defaultTaskTemplate(a: std.mem.Allocator) !TaskTemplate {
    var out = std.array_list.Managed(FieldDef).init(a);
    errdefer {
        for (out.items) |*f| f.deinit(a);
        out.deinit();
    }

    try out.append(try fieldAlloc(a, "status", .string, true, "open", &.{ "open", "in-progress", "blocked", "done" }));
    try out.append(try fieldAlloc(a, "priority", .string, false, null, &.{ "critical", "high", "medium", "low" }));
    try out.append(try fieldAlloc(a, "owner", .string, false, null, &.{}));
    try out.append(try fieldAlloc(a, "project", .string, false, null, &.{}));
    try out.append(try fieldAlloc(a, "due", .date, false, null, &.{}));
    try out.append(try fieldAlloc(a, "tags", .string_array, false, null, &.{}));
    try out.append(try fieldAlloc(a, "estimate", .string, false, null, &.{}));
    try out.append(try fieldAlloc(a, "parent", .string, false, null, &.{}));
    try out.append(try fieldAlloc(a, "depends_on", .string_array, false, null, &.{}));

    return .{ .fields = try out.toOwnedSlice() };
}

fn fieldAlloc(
    a: std.mem.Allocator,
    name: []const u8,
    typ: FieldType,
    required: bool,
    default_value: ?[]const u8,
    enum_values: []const []const u8,
) !FieldDef {
    var enum_duped = std.array_list.Managed([]u8).init(a);
    defer enum_duped.deinit();
    for (enum_values) |ev| try enum_duped.append(try a.dupe(u8, ev));

    return .{
        .name = try a.dupe(u8, name),
        .typ = typ,
        .required = required,
        .default_string = if (default_value) |v| try a.dupe(u8, v) else null,
        .enum_values = try enum_duped.toOwnedSlice(),
    };
}

fn applyTaskTemplateDefaultsAndValidate(a: std.mem.Allocator, fm: *Frontmatter, template: TaskTemplate) !void {
    for (template.fields) |f| {
        const maybe = fm.get(f.name);
        if (maybe == null) {
            if (f.default_string) |d| {
                try fm.setStringDup(a, f.name, d);
            } else if (f.required) {
                return error.RequiredFieldMissing;
            }
            continue;
        }

        const v = maybe.?;
        switch (f.typ) {
            .string, .date => {
                if (v != .string) return error.TemplateTypeMismatch;
                if (f.enum_values.len > 0) {
                    const s = v.string;
                    var ok = false;
                    for (f.enum_values) |ev| {
                        if (std.mem.eql(u8, ev, s)) {
                            ok = true;
                            break;
                        }
                    }
                    if (!ok) return error.TemplateEnumViolation;
                }
            },
            .string_array => if (v != .list) return error.TemplateTypeMismatch,
            .boolean => if (v != .boolean) return error.TemplateTypeMismatch,
        }
    }
}

fn parseDocAlloc(a: std.mem.Allocator, bytes: []const u8) !ParsedDoc {
    const maybe = extractFrontmatterSlice(bytes);
    if (maybe == null) {
        return .{ .fm = Frontmatter.init(a), .body = try a.dupe(u8, bytes) };
    }

    const slices = maybe.?;
    const fm_text = slices;

    var fm = Frontmatter.init(a);
    errdefer fm.deinit(a);

    var lines = std.mem.splitScalar(u8, fm_text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const t = std.mem.trim(u8, line, " \t");
        if (t.len == 0) continue;
        if (t[0] == '#') continue;

        const sep = std.mem.indexOfScalar(u8, t, ':') orelse continue;
        const key = std.mem.trim(u8, t[0..sep], " \t");
        const raw_val = std.mem.trim(u8, t[sep + 1 ..], " \t");

        if (raw_val.len == 0) {
            try fm.setStringDup(a, key, "");
            continue;
        }

        if (raw_val[0] == '[' and raw_val[raw_val.len - 1] == ']') {
            const arr = try parseYamlArrayAlloc(a, raw_val);
            defer freeStringList(a, arr);
            try fm.setListDup(a, key, arr);
            continue;
        }

        if (std.mem.eql(u8, raw_val, "true")) {
            try fm.setBool(a, key, true);
            continue;
        }
        if (std.mem.eql(u8, raw_val, "false")) {
            try fm.setBool(a, key, false);
            continue;
        }

        try fm.setStringDup(a, key, trimYamlScalar(raw_val));
    }

    const body = try bodySliceDup(a, bytes);
    return .{ .fm = fm, .body = body };
}

fn renderTaskDocAlloc(a: std.mem.Allocator, fm: Frontmatter, body: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    try aw.writer.writeAll("---\n");

    for (preferred_frontmatter_keys) |k| {
        const v = fm.get(k) orelse continue;
        try writeFmEntry(&aw.writer, k, v);
    }

    var rest = std.array_list.Managed([]const u8).init(a);
    defer rest.deinit();

    var it = fm.map.iterator();
    while (it.next()) |e| {
        if (isPreferredKey(e.key_ptr.*)) continue;
        try rest.append(e.key_ptr.*);
    }

    std.sort.block([]const u8, rest.items, {}, struct {
        fn lt(_: void, a_: []const u8, b_: []const u8) bool {
            return std.mem.lessThan(u8, a_, b_);
        }
    }.lt);

    for (rest.items) |k| {
        const v = fm.get(k).?;
        try writeFmEntry(&aw.writer, k, v);
    }

    try aw.writer.writeAll("---\n");

    if (body.len > 0) {
        try aw.writer.writeAll(body);
        if (body[body.len - 1] != '\n') try aw.writer.writeAll("\n");
    }

    return try aw.toOwnedSlice();
}

fn writeFmEntry(w: *std.Io.Writer, key: []const u8, v: FrontmatterValue) !void {
    try w.print("{s}: ", .{key});
    switch (v) {
        .string => |s| {
            try writeYamlQuoted(w, s);
            try w.writeAll("\n");
        },
        .boolean => |b| {
            try w.print("{s}\n", .{if (b) "true" else "false"});
        },
        .list => |arr| {
            try w.writeAll("[");
            for (arr, 0..) |it, i| {
                if (i > 0) try w.writeAll(", ");
                try writeYamlQuoted(w, it);
            }
            try w.writeAll("]\n");
        },
    }
}

fn writeYamlQuoted(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeAll("\"");
    for (s) |c| {
        if (c == '\\' or c == '"') {
            try w.writeByte('\\');
        }
        try w.writeByte(c);
    }
    try w.writeAll("\"");
}

fn parseYamlArrayAlloc(a: std.mem.Allocator, raw: []const u8) ![][]u8 {
    if (raw.len < 2 or raw[0] != '[' or raw[raw.len - 1] != ']') return error.InvalidArray;
    const inner = std.mem.trim(u8, raw[1 .. raw.len - 1], " \t");

    var out = std.array_list.Managed([]u8).init(a);
    errdefer {
        for (out.items) |it| a.free(it);
        out.deinit();
    }

    if (inner.len == 0) return try out.toOwnedSlice();

    var i: usize = 0;
    var start: usize = 0;
    var in_str = false;
    while (i <= inner.len) : (i += 1) {
        const at_end = i == inner.len;
        const c = if (at_end) ',' else inner[i];

        if (!at_end and (c == '"' or c == '\'')) {
            in_str = !in_str;
        }

        if ((!in_str and c == ',') or at_end) {
            const part = std.mem.trim(u8, inner[start..i], " \t");
            if (part.len > 0) {
                try out.append(try a.dupe(u8, trimYamlScalar(part)));
            }
            start = i + 1;
        }
    }

    return try out.toOwnedSlice();
}

fn parseCommaListAlloc(a: std.mem.Allocator, raw: []const u8) ![][]u8 {
    var out = std.array_list.Managed([]u8).init(a);
    errdefer {
        for (out.items) |it| a.free(it);
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |piece| {
        const p = std.mem.trim(u8, piece, " \t\r\n");
        if (p.len == 0) continue;
        try out.append(try a.dupe(u8, p));
    }
    return try out.toOwnedSlice();
}

fn statusAllowed(status: []const u8, allowed: []const []const u8) bool {
    for (allowed) |a_status| {
        if (std.mem.eql(u8, status, a_status)) return true;
    }
    return false;
}

fn freeStringList(a: std.mem.Allocator, list: [][]u8) void {
    for (list) |it| a.free(it);
    a.free(list);
}

fn extractFrontmatterSlice(content: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, content, "---")) return null;

    var lines = std.mem.splitScalar(u8, content, '\n');
    const first = lines.next() orelse return null;
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, first, "\r"), "---")) return null;

    var offset: usize = first.len;
    if (offset < content.len and content[offset] == '\n') offset += 1;

    var idx: usize = offset;
    while (idx <= content.len) {
        const next_nl = std.mem.indexOfScalarPos(u8, content, idx, '\n') orelse content.len;
        const line = std.mem.trimEnd(u8, content[idx..next_nl], "\r");
        if (std.mem.eql(u8, line, "---")) {
            return content[offset..idx];
        }
        if (next_nl == content.len) break;
        idx = next_nl + 1;
    }

    return null;
}

fn bodySliceDup(a: std.mem.Allocator, content: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, content, "---")) return try a.dupe(u8, content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    const first = lines.next() orelse return try a.dupe(u8, content);
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, first, "\r"), "---")) return try a.dupe(u8, content);

    var idx: usize = first.len;
    if (idx < content.len and content[idx] == '\n') idx += 1;

    while (idx <= content.len) {
        const next_nl = std.mem.indexOfScalarPos(u8, content, idx, '\n') orelse content.len;
        const line = std.mem.trimEnd(u8, content[idx..next_nl], "\r");
        if (std.mem.eql(u8, line, "---")) {
            const body_start = if (next_nl < content.len) next_nl + 1 else next_nl;
            return try a.dupe(u8, content[body_start..]);
        }
        if (next_nl == content.len) break;
        idx = next_nl + 1;
    }

    return try a.dupe(u8, content);
}

fn appendTransitionLedgerAlloc(
    a: std.mem.Allocator,
    body: []const u8,
    from_status: []const u8,
    to_status: []const u8,
    reason: ?[]const u8,
    ts: []const u8,
) ![]u8 {
    const line = if (reason) |r|
        try std.fmt.allocPrint(a, "- {s}: {s} -> {s} ({s})\n", .{ ts, from_status, to_status, r })
    else
        try std.fmt.allocPrint(a, "- {s}: {s} -> {s}\n", .{ ts, from_status, to_status });
    defer a.free(line);

    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();

    const trimmed = std.mem.trimEnd(u8, body, "\r\n");
    if (trimmed.len > 0) {
        try aw.writer.writeAll(trimmed);
        try aw.writer.writeAll("\n");
    }

    if (std.mem.indexOf(u8, trimmed, "## Transition Ledger") == null) {
        if (trimmed.len > 0) try aw.writer.writeAll("\n");
        try aw.writer.writeAll("## Transition Ledger\n");
    }

    try aw.writer.writeAll(line);
    return try aw.toOwnedSlice();
}

fn countLeadingSpaces(line: []const u8) usize {
    var n: usize = 0;
    while (n < line.len and line[n] == ' ') : (n += 1) {}
    return n;
}

fn trimYamlScalar(raw: []const u8) []const u8 {
    const t = std.mem.trim(u8, raw, " \t");
    if (t.len >= 2 and ((t[0] == '"' and t[t.len - 1] == '"') or (t[0] == '\'' and t[t.len - 1] == '\''))) {
        return t[1 .. t.len - 1];
    }
    return t;
}

fn resolveMemoryRootAlloc(a: std.mem.Allocator, cfg: config.ValidatedConfig) ![]u8 {
    return if (std.fs.path.isAbsolute(cfg.raw.memory.root))
        try a.dupe(u8, cfg.raw.memory.root)
    else
        try std.fs.path.join(a, &.{ cfg.raw.security.workspace_root, cfg.raw.memory.root });
}

fn resolveTemplatesDirAlloc(a: std.mem.Allocator, cfg: config.ValidatedConfig) ![]u8 {
    return if (std.fs.path.isAbsolute(cfg.raw.memory.primitives.templates_dir))
        try a.dupe(u8, cfg.raw.memory.primitives.templates_dir)
    else
        try std.fs.path.join(a, &.{ cfg.raw.security.workspace_root, cfg.raw.memory.primitives.templates_dir });
}

fn ensurePrimitiveDirs(io: std.Io, memory_root: []const u8, templates_dir: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, memory_root);
    try std.Io.Dir.cwd().createDirPath(io, templates_dir);

    const dirs = [_][]const u8{ "tasks", "projects", "decisions", "lessons", "people" };
    for (dirs) |d| {
        var buf: [1024]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ memory_root, d }) catch continue;
        try std.Io.Dir.cwd().createDirPath(io, path);
    }
}

fn findTaskSlugByEventIdAlloc(a: std.mem.Allocator, io: std.Io, tasks_dir: []const u8, event_id: []const u8) !?[]u8 {
    var dir = std.Io.Dir.cwd().openDir(io, tasks_dir, .{}) catch return null;
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |ent| {
        if (ent.kind != .file or !std.mem.endsWith(u8, ent.name, ".md")) continue;
        const path = try std.fs.path.join(a, &.{ tasks_dir, ent.name });
        defer a.free(path);

        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(512 * 1024)) catch continue;
        defer a.free(bytes);

        var doc = parseDocAlloc(a, bytes) catch continue;
        defer doc.deinit(a);

        const found = doc.fm.getString("event_id") orelse continue;
        if (std.mem.eql(u8, found, event_id)) return try a.dupe(u8, fileStem(ent.name));
    }
    return null;
}

fn nextTaskFileNameAlloc(a: std.mem.Allocator, io: std.Io, tasks_dir: []const u8, base_slug: []const u8) ![]u8 {
    var n: usize = 1;
    while (true) : (n += 1) {
        const name = if (n == 1)
            try std.fmt.allocPrint(a, "{s}.md", .{base_slug})
        else
            try std.fmt.allocPrint(a, "{s}-{d}.md", .{ base_slug, n });

        const path = try std.fs.path.join(a, &.{ tasks_dir, name });
        defer a.free(path);

        _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch {
            return name;
        };
        a.free(name);
    }
}

fn slugifyAlloc(a: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(a);
    defer out.deinit();

    var prev_dash = false;
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c)) {
            try out.append(std.ascii.toLower(c));
            prev_dash = false;
            continue;
        }

        if (!prev_dash) {
            try out.append('-');
            prev_dash = true;
        }
    }

    while (out.items.len > 0 and out.items[0] == '-') _ = out.orderedRemove(0);
    while (out.items.len > 0 and out.items[out.items.len - 1] == '-') _ = out.pop();

    if (out.items.len == 0) try out.appendSlice("task");
    return try out.toOwnedSlice();
}

fn fileStem(name: []const u8) []const u8 {
    if (std.mem.endsWith(u8, name, ".md")) return name[0 .. name.len - 3];
    return name;
}

fn isPreferredKey(key: []const u8) bool {
    for (preferred_frontmatter_keys) |k| {
        if (std.mem.eql(u8, key, k)) return true;
    }
    return false;
}

fn writeFile(io: std.Io, path: []const u8, bytes: []const u8) !void {
    var f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var w = f.writer(io, &buf);
    try w.interface.writeAll(bytes);
    try w.flush();
}

fn nowUnixMs(io: anytype) i64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return ts.toMilliseconds();
}

const preferred_frontmatter_keys = [_][]const u8{
    "title",
    "status",
    "priority",
    "owner",
    "project",
    "due",
    "tags",
    "estimate",
    "parent",
    "depends_on",
    "event_id",
    "created_at",
    "updated_at",
};

pub const default_task_template_md =
    \\---
    \\primitive: task
    \\fields:
    \\  status:
    \\    type: string
    \\    required: true
    \\    default: open
    \\    enum: [open, in-progress, blocked, done]
    \\  priority:
    \\    type: string
    \\    enum: [critical, high, medium, low]
    \\  owner:
    \\    type: string
    \\  project:
    \\    type: string
    \\  due:
    \\    type: date
    \\  tags:
    \\    type: string[]
    \\  estimate:
    \\    type: string
    \\  parent:
    \\    type: string
    \\  depends_on:
    \\    type: string[]
    \\---
    ;
