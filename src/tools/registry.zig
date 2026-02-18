const std = @import("std");
const manifest_mod = @import("manifest.zig");
const fingerprint = @import("registry_fingerprint.zig");
const generated = @import("registry_generated.zig");

pub const Entry = generated.Entry;
pub const entries = generated.entries;

pub const Match = enum {
    ok,
    unregistered,
    abi_mismatch,
};

pub fn contains(tool_name: []const u8) bool {
    return find(tool_name) != null;
}

pub fn isBuiltin(tool_name: []const u8) bool {
    return contains(tool_name);
}

pub fn find(tool_name: []const u8) ?Entry {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.tool_name, tool_name)) return entry;
    }
    return null;
}

pub fn checkManifest(a: std.mem.Allocator, manifest: manifest_mod.Manifest) !Match {
    const entry = find(manifest.tool_name) orelse return .unregistered;

    const fp = try fingerprint.schemaFingerprintHexAlloc(a, manifest.args);
    defer a.free(fp);

    if (!std.mem.eql(u8, entry.schema_fingerprint_hex, fp)) return .abi_mismatch;
    return .ok;
}
