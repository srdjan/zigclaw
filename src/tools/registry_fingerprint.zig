const std = @import("std");
const manifest_mod = @import("manifest.zig");

pub fn schemaFingerprintHexAlloc(a: std.mem.Allocator, args: manifest_mod.ArgSchema) ![]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});

    hasher.update("kind=");
    hasher.update(@tagName(args.kind));

    const required_idxs = try a.alloc(usize, args.required.len);
    defer a.free(required_idxs);
    for (required_idxs, 0..) |*idx, i| idx.* = i;
    std.sort.block(usize, required_idxs, args.required, struct {
        fn lessThan(required: []const []const u8, ai: usize, bi: usize) bool {
            return std.mem.lessThan(u8, required[ai], required[bi]);
        }
    }.lessThan);

    hasher.update(";required=");
    for (required_idxs) |idx| {
        hasher.update(args.required[idx]);
        hasher.update(",");
    }

    const prop_idxs = try a.alloc(usize, args.properties.len);
    defer a.free(prop_idxs);
    for (prop_idxs, 0..) |*idx, i| idx.* = i;
    std.sort.block(usize, prop_idxs, args.properties, struct {
        fn lessThan(props: []const manifest_mod.ArgSchema.Property, ai: usize, bi: usize) bool {
            return std.mem.lessThan(u8, props[ai].name, props[bi].name);
        }
    }.lessThan);

    for (prop_idxs) |idx| {
        const prop = args.properties[idx];
        hasher.update(";prop=");
        hasher.update(prop.name);
        hasher.update(":");
        hasher.update(@tagName(prop.schema.typ));

        if (prop.schema.max_length) |max_length| {
            hasher.update(";max_length=");
            var buf: [32]u8 = undefined;
            const text = try std.fmt.bufPrint(&buf, "{d}", .{max_length});
            hasher.update(text);
        }

        if (prop.schema.min_int) |min_int| {
            hasher.update(";min=");
            var buf: [32]u8 = undefined;
            const text = try std.fmt.bufPrint(&buf, "{d}", .{min_int});
            hasher.update(text);
        }

        if (prop.schema.max_int) |max_int| {
            hasher.update(";max=");
            var buf: [32]u8 = undefined;
            const text = try std.fmt.bufPrint(&buf, "{d}", .{max_int});
            hasher.update(text);
        }

        const enum_idxs = try a.alloc(usize, prop.schema.enum_values.len);
        defer a.free(enum_idxs);
        for (enum_idxs, 0..) |*enum_idx, i| enum_idx.* = i;
        std.sort.block(usize, enum_idxs, prop.schema.enum_values, struct {
            fn lessThan(values: []const []const u8, ai: usize, bi: usize) bool {
                return std.mem.lessThan(u8, values[ai], values[bi]);
            }
        }.lessThan);

        hasher.update(";enum=");
        for (enum_idxs) |enum_idx| {
            hasher.update(prop.schema.enum_values[enum_idx]);
            hasher.update(",");
        }
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return try hexAlloc(a, &digest);
}

fn hexAlloc(a: std.mem.Allocator, digest: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    var out = try a.alloc(u8, digest.len * 2);
    for (digest, 0..) |b, i| {
        out[i * 2] = hex_chars[(b >> 4) & 0x0f];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out;
}
