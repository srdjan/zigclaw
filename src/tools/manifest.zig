const std = @import("std");

// Reuse the KeyMap TOML parser from config.zig (P1) by importing a small internal module.
// To avoid circular deps, we embed a tiny TOML KeyMap parser here (subset), similar to P1.

pub const Value = union(enum) {
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

pub const KeyMap = struct {
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

pub const Manifest = struct {
    tool_name: []const u8,
    version: []const u8,
    description: []const u8,
    requires_network: bool,
    max_runtime_ms: u32,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
    args: ArgSchema,

    pub fn toJsonAlloc(self: Manifest, a: std.mem.Allocator) ![]u8 {
        var stream = std.json.StringifyStream.init(a);
        defer stream.deinit();

        try stream.beginObject();
        try stream.objectField("tool_name"); try stream.write(self.tool_name);
        try stream.objectField("version"); try stream.write(self.version);
        try stream.objectField("description"); try stream.write(self.description);
        try stream.objectField("requires_network"); try stream.write(self.requires_network);
        try stream.objectField("max_runtime_ms"); try stream.write(self.max_runtime_ms);
        try stream.objectField("max_stdout_bytes"); try stream.write(self.max_stdout_bytes);
        try stream.objectField("max_stderr_bytes"); try stream.write(self.max_stderr_bytes);
        try stream.objectField("args");
        try self.args.writeJson(stream);
        try stream.endObject();

        return try stream.toOwnedSlice();
    }
};

pub const ArgSchema = struct {
    kind: Kind,
    required: []const []const u8,
    properties: []Property,

    pub const Kind = enum { object };

    pub const Property = struct {
        name: []const u8,
        schema: PropSchema,
    };

    pub const PropSchema = struct {
        typ: Type,
        // constraints (subset)
        max_length: ?usize = null,
        enum_values: []const []const u8 = &.{},
        min_int: ?i64 = null,
        max_int: ?i64 = null,

        pub const Type = enum { string, integer, boolean };
    };

    pub fn writeJson(self: ArgSchema, stream: anytype) !void {
        try stream.beginObject();
        try stream.objectField("type"); try stream.write(@tagName(self.kind));
        try stream.objectField("required");
        try stream.beginArray();
        for (self.required) |r| try stream.write(r);
        try stream.endArray();

        try stream.objectField("properties");
        try stream.beginObject();
        for (self.properties) |p| {
            try stream.objectField(p.name);
            try stream.beginObject();
            try stream.objectField("type"); try stream.write(@tagName(p.schema.typ));
            if (p.schema.max_length) |ml| { try stream.objectField("max_length"); try stream.write(ml); }
            if (p.schema.min_int) |mi| { try stream.objectField("min"); try stream.write(mi); }
            if (p.schema.max_int) |ma| { try stream.objectField("max"); try stream.write(ma); }
            if (p.schema.enum_values.len > 0) {
                try stream.objectField("enum");
                try stream.beginArray();
                for (p.schema.enum_values) |ev| try stream.write(ev);
                try stream.endArray();
            }
            try stream.endObject();
        }
        try stream.endObject();

        try stream.endObject();
    }
};

pub fn loadManifest(a: std.mem.Allocator, path: []const u8) !ManifestOwned {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const bytes = try file.readToEndAlloc(a, 256 * 1024);
    defer a.free(bytes);

    var km = try parseTomlKeyMap(a, bytes);
    errdefer km.deinit(a);

    const m = try buildManifest(a, &km);
    // km deinit happens in owned wrapper deinit (so we can keep referenced strings stable)
    return .{ .km = km, .manifest = m };
}

pub const ManifestOwned = struct {
    km: KeyMap,
    manifest: Manifest,

    pub fn deinit(self: *ManifestOwned, a: std.mem.Allocator) void {
        // manifest fields point into km-owned allocations, so just free km + derived slices we allocated
        // free required + properties arrays + nested enum arrays
        for (self.manifest.args.required) |s| a.free(s);
        a.free(self.manifest.args.required);

        for (self.manifest.args.properties) |p| {
            a.free(p.name);
            for (p.schema.enum_values) |ev| a.free(ev);
            a.free(p.schema.enum_values);
        }
        a.free(self.manifest.args.properties);

        self.km.deinit(a);
    }
};

fn buildManifest(a: std.mem.Allocator, km: *const KeyMap) !Manifest {
    const tool_name = try getStringDup(a, km, "tool_name");
    const version = try getStringDup(a, km, "version");
    const description = try getStringDup(a, km, "description");

    const requires_network = getBool(km, "requires_network") orelse false;
    const max_runtime_ms = if (getInt(km, "max_runtime_ms")) |v| std.math.cast(u32, v) orelse return error.Range else 2000;
    const max_stdout_bytes = if (getInt(km, "max_stdout_bytes")) |v| std.math.cast(usize, v) orelse return error.Range else 65536;
    const max_stderr_bytes = if (getInt(km, "max_stderr_bytes")) |v| std.math.cast(usize, v) orelse return error.Range else 65536;

    // args.type
    const args_type = try getString(km, "args.type");
    if (!std.mem.eql(u8, args_type, "object")) return error.UnsupportedArgsType;

    const required = try getStringArrayDup(a, km, "args.required");

    // properties: find all keys like args.properties.<name>.type
    var props = std.ArrayList(ArgSchema.Property).init(a);
    errdefer {
        for (props.items) |p| {
            a.free(p.name);
            for (p.schema.enum_values) |ev| a.free(ev);
            a.free(p.schema.enum_values);
        }
        props.deinit();
    }

    var it = km.map.iterator();
    while (it.next()) |e| {
        const k = e.key_ptr.*;
        if (!std.mem.startsWith(u8, k, "args.properties.")) continue;

        // match: args.properties.<name>.type
        const rest = k["args.properties.".len..];
        const dot = std.mem.indexOfScalar(u8, rest, '.') orelse continue;
        const name = rest[0..dot];
        const field = rest[dot + 1 ..];

        if (!std.mem.eql(u8, field, "type")) continue;

        // build this property schema by reading sibling keys
        const type_key = k;
        const typ_s = try getString(km, type_key);

        const typ = if (std.mem.eql(u8, typ_s, "string")) ArgSchema.PropSchema.Type.string
            else if (std.mem.eql(u8, typ_s, "integer")) ArgSchema.PropSchema.Type.integer
            else if (std.mem.eql(u8, typ_s, "boolean")) ArgSchema.PropSchema.Type.boolean
            else return error.UnsupportedPropType;

        const max_len_key = try std.fmt.allocPrint(a, "args.properties.{s}.max_length", .{name});
        defer a.free(max_len_key);
        const enum_key = try std.fmt.allocPrint(a, "args.properties.{s}.enum", .{name});
        defer a.free(enum_key);
        const min_key = try std.fmt.allocPrint(a, "args.properties.{s}.min", .{name});
        defer a.free(min_key);
        const max_key = try std.fmt.allocPrint(a, "args.properties.{s}.max", .{name});
        defer a.free(max_key);

        const max_length = if (getInt(km, max_len_key)) |ml| @as(usize, @intCast(ml)) else null;
        const enum_values = getStringArrayDup(a, km, enum_key) catch |err| switch (err) {
            error.MissingKey, error.TypeMismatch => &.{},
            else => return err,
        };
        const min_int = getInt(km, min_key);
        const max_int = getInt(km, max_key);

        try props.append(.{
            .name = try a.dupe(u8, name),
            .schema = .{
                .typ = typ,
                .max_length = max_length,
                .enum_values = enum_values,
                .min_int = min_int,
                .max_int = max_int,
            },
        });
    }

    // stable sort by name
    std.sort.block(ArgSchema.Property, props.items, {}, struct {
        fn lt(_: void, a_: ArgSchema.Property, b_: ArgSchema.Property) bool {
            return std.mem.lessThan(u8, a_.name, b_.name);
        }
    }.lt);

    return .{
        .tool_name = tool_name,
        .version = version,
        .description = description,
        .requires_network = requires_network,
        .max_runtime_ms = max_runtime_ms,
        .max_stdout_bytes = max_stdout_bytes,
        .max_stderr_bytes = max_stderr_bytes,
        .args = .{
            .kind = .object,
            .required = required,
            .properties = try props.toOwnedSlice(),
        },
    };
}

// ---------------- TOML subset parser (same capabilities as P1) ----------------

fn parseTomlKeyMap(a: std.mem.Allocator, input: []const u8) !KeyMap {
    var km = KeyMap.init(a);

    var table_prefix = std.ArrayList([]const u8).init(a);
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

    return km;
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

fn parseValue(a: std.mem.Allocator, raw: []const u8) !Value {
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

fn parseBasicString(a: std.mem.Allocator, t: []const u8) ![]const u8 {
    if (t.len < 2 or t[0] != '"' or t[t.len - 1] != '"') return error.InvalidString;
    const inner = t[1 .. t.len - 1];

    var out = std.ArrayList(u8).init(a);
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

fn parseArray(a: std.mem.Allocator, t: []const u8) ![]Value {
    if (t.len < 2 or t[0] != '[' or t[t.len - 1] != ']') return error.InvalidArray;
    var inner = std.mem.trim(u8, t[1 .. t.len - 1], " \t\r");

    var items = std.ArrayList(Value).init(a);
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

// -------------------- KeyMap getters --------------------

fn getString(km: *const KeyMap, key: []const u8) ![]const u8 {
    const v = km.map.get(key) orelse return error.MissingKey;
    return switch (v) {
        .string => |s| s,
        else => error.TypeMismatch,
    };
}
fn getStringDup(a: std.mem.Allocator, km: *const KeyMap, key: []const u8) ![]const u8 {
    return try a.dupe(u8, try getString(km, key));
}
fn getBool(km: *const KeyMap, key: []const u8) ?bool {
    const v = km.map.get(key) orelse return null;
    return switch (v) {
        .boolean => |b| b,
        else => null,
    };
}
fn getInt(km: *const KeyMap, key: []const u8) ?i64 {
    const v = km.map.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}
fn getStringArrayDup(a: std.mem.Allocator, km: *const KeyMap, key: []const u8) ![]const []const u8 {
    const v = km.map.get(key) orelse return error.MissingKey;
    return switch (v) {
        .array => |arr| {
            var out = std.ArrayList([]const u8).init(a);
            errdefer {
                for (out.items) |s| a.free(s);
                out.deinit();
            }
            for (arr) |it| {
                if (it != .string) return error.TypeMismatch;
                try out.append(try a.dupe(u8, it.string));
            }
            return try out.toOwnedSlice();
        },
        else => error.TypeMismatch,
    };
}
