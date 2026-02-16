const std = @import("std");
const crypto = @import("crypto.zig");

pub const Vault = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap([]const u8),

    pub fn init(a: std.mem.Allocator) Vault {
        return .{
            .allocator = a,
            .entries = std.StringHashMap([]const u8).init(a),
        };
    }

    pub fn deinit(self: *Vault) void {
        var it = self.entries.iterator();
        while (it.next()) |e| {
            // Zero out sensitive values before freeing
            const val_ptr: [*]u8 = @constCast(e.value_ptr.*.ptr);
            crypto.zeroize(val_ptr[0..e.value_ptr.*.len]);
            self.allocator.free(e.value_ptr.*);
            self.allocator.free(e.key_ptr.*);
        }
        self.entries.deinit();
    }

    pub fn get(self: *const Vault, name: []const u8) ?[]const u8 {
        return self.entries.get(name);
    }

    pub fn set(self: *Vault, name: []const u8, value: []const u8) !void {
        const key = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(key);
        const val = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(val);

        if (self.entries.fetchRemove(name)) |old| {
            const old_val_ptr: [*]u8 = @constCast(old.value.ptr);
            crypto.zeroize(old_val_ptr[0..old.value.len]);
            self.allocator.free(old.value);
            self.allocator.free(old.key);
        }
        try self.entries.put(key, val);
    }

    pub fn delete(self: *Vault, name: []const u8) bool {
        if (self.entries.fetchRemove(name)) |old| {
            const old_val_ptr: [*]u8 = @constCast(old.value.ptr);
            crypto.zeroize(old_val_ptr[0..old.value.len]);
            self.allocator.free(old.value);
            self.allocator.free(old.key);
            return true;
        }
        return false;
    }

    pub fn list(self: *const Vault, a: std.mem.Allocator) ![][]const u8 {
        var names = std.array_list.Managed([]const u8).init(a);
        var it = self.entries.keyIterator();
        while (it.next()) |k| {
            try names.append(try a.dupe(u8, k.*));
        }
        return try names.toOwnedSlice();
    }
};

pub fn open(a: std.mem.Allocator, io: std.Io, path: []const u8, passphrase: []const u8) !Vault {
    const blob = std.Io.Dir.cwd().readFileAlloc(io, path, a, std.Io.Limit.limited(4 * 1024 * 1024)) catch {
        // File doesn't exist: return empty vault
        return Vault.init(a);
    };
    defer a.free(blob);

    if (blob.len == 0) return Vault.init(a);

    const salt = try crypto.extractSalt(blob);
    var key = try crypto.deriveKey(a, io, passphrase, salt);
    defer crypto.zeroize(&key);

    const plaintext = try crypto.decrypt(a, key, blob);
    defer {
        crypto.zeroize(plaintext);
        a.free(plaintext);
    }

    // Parse JSON object
    var vault = Vault.init(a);
    errdefer vault.deinit();

    var parsed = std.json.parseFromSlice(std.json.Value, a, plaintext, .{}) catch return error.InvalidVaultData;
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidVaultData;

    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .string) continue;
        try vault.set(entry.key_ptr.*, entry.value_ptr.string);
    }

    return vault;
}

pub fn save(vault: *const Vault, a: std.mem.Allocator, io: std.Io, path: []const u8, passphrase: []const u8) !void {
    // Serialize entries to JSON
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.beginObject();
    var it = vault.entries.iterator();
    while (it.next()) |entry| {
        try stream.objectField(entry.key_ptr.*);
        try stream.write(entry.value_ptr.*);
    }
    try stream.endObject();

    const json = try aw.toOwnedSlice();
    defer {
        crypto.zeroize(json);
        a.free(json);
    }

    // Generate fresh salt and derive key
    var salt: [crypto.salt_len]u8 = undefined;
    io.random(&salt);
    var key = try crypto.deriveKey(a, io, passphrase, salt);
    defer crypto.zeroize(&key);

    // Encrypt
    const blob = try crypto.encrypt(a, io, key, salt, json);
    defer a.free(blob);

    // Write file
    const dir_path = std.fs.path.dirname(path);
    if (dir_path) |dp| {
        std.Io.Dir.cwd().createDirPath(io, dp) catch {};
    }

    var f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer f.close(io);
    var buf: [8192]u8 = undefined;
    var w = f.writer(io, &buf);
    try w.interface.writeAll(blob);
    try w.flush();
}
