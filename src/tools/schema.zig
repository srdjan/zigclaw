const std = @import("std");
const manifest = @import("manifest.zig");

pub const ValidationError = error{
    InvalidJson,
    NotObject,
    MissingRequired,
    TypeMismatch,
    TooLong,
    NotInEnum,
    OutOfRange,
};

pub fn validateArgs(schema: manifest.ArgSchema, args_json: []const u8) ValidationError!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var parsed = std.json.parseFromSlice(std.json.Value, a, args_json, .{}) catch return ValidationError.InvalidJson;
    const v = parsed.value;

    if (v != .object) return ValidationError.NotObject;

    const obj = v.object;

    // required
    for (schema.required) |req| {
        if (obj.get(req) == null) return ValidationError.MissingRequired;
    }

    // properties constraints (only those declared)
    for (schema.properties) |p| {
        const maybe = obj.get(p.name);
        if (maybe == null) continue;

        const val = maybe.?;
        switch (p.schema.typ) {
            .string => {
                if (val != .string) return ValidationError.TypeMismatch;
                const s = val.string;
                if (p.schema.max_length) |ml| {
                    if (s.len > ml) return ValidationError.TooLong;
                }
                if (p.schema.enum_values.len > 0) {
                    var ok = false;
                    for (p.schema.enum_values) |ev| {
                        if (std.mem.eql(u8, ev, s)) {
                            ok = true;
                            break;
                        }
                    }
                    if (!ok) return ValidationError.NotInEnum;
                }
            },
            .integer => {
                if (val != .integer) return ValidationError.TypeMismatch;
                const i = val.integer;
                if (p.schema.min_int) |mi| {
                    if (i < mi) return ValidationError.OutOfRange;
                }
                if (p.schema.max_int) |ma| {
                    if (i > ma) return ValidationError.OutOfRange;
                }
            },
            .boolean => {
                if (val != .bool) return ValidationError.TypeMismatch;
            },
        }
    }
}
