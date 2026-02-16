const std = @import("std");

pub const Sibling = struct {
    hash: [32]u8,
    is_left: bool,
};

pub const MerkleProof = struct {
    leaf_index: usize,
    leaf_hash: [32]u8,
    siblings: []Sibling,

    pub fn deinit(self: *MerkleProof, a: std.mem.Allocator) void {
        a.free(self.siblings);
    }
};

pub const MerkleTree = struct {
    allocator: std.mem.Allocator,
    leaves: std.array_list.Managed([32]u8),

    pub fn init(a: std.mem.Allocator) MerkleTree {
        return .{
            .allocator = a,
            .leaves = std.array_list.Managed([32]u8).init(a),
        };
    }

    pub fn deinit(self: *MerkleTree) void {
        self.leaves.deinit();
    }

    pub fn addLeaf(self: *MerkleTree, event_json: []const u8) !void {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(event_json);
        var digest: [32]u8 = undefined;
        h.final(&digest);
        try self.leaves.append(digest);
    }

    pub fn addLeafHash(self: *MerkleTree, leaf_hash: [32]u8) !void {
        try self.leaves.append(leaf_hash);
    }

    pub fn leafCount(self: *const MerkleTree) usize {
        return self.leaves.items.len;
    }

    pub fn leafHashes(self: *const MerkleTree) []const [32]u8 {
        return self.leaves.items;
    }

    pub fn computeRoot(self: *const MerkleTree) ![32]u8 {
        if (self.leaves.items.len == 0) return hashEmpty();
        if (self.leaves.items.len == 1) return self.leaves.items[0];

        var level = try self.allocator.alloc([32]u8, self.leaves.items.len);
        defer self.allocator.free(level);
        @memcpy(level, self.leaves.items);

        var level_len = level.len;
        while (level_len > 1) {
            const next_len = (level_len + 1) / 2;
            var next = try self.allocator.alloc([32]u8, next_len);
            defer self.allocator.free(next);

            var i: usize = 0;
            while (i < level_len) : (i += 2) {
                const left = level[i];
                const right = if (i + 1 < level_len) level[i + 1] else level[i];
                next[i / 2] = hashPair(left, right);
            }

            @memcpy(level[0..next_len], next);
            level_len = next_len;
        }
        return level[0];
    }

    pub fn proof(self: *const MerkleTree, leaf_index: usize) !MerkleProof {
        if (leaf_index >= self.leaves.items.len) return error.IndexOutOfBounds;

        if (self.leaves.items.len <= 1) {
            return .{
                .leaf_index = leaf_index,
                .leaf_hash = self.leaves.items[leaf_index],
                .siblings = try self.allocator.dupe(Sibling, &.{}),
            };
        }

        var level = try self.allocator.alloc([32]u8, self.leaves.items.len);
        defer self.allocator.free(level);
        @memcpy(level, self.leaves.items);

        var level_len = level.len;
        var idx = leaf_index;

        var siblings = std.array_list.Managed(Sibling).init(self.allocator);
        errdefer siblings.deinit();

        while (level_len > 1) {
            const sibling_idx: usize = if (idx % 2 == 0) idx + 1 else idx - 1;
            const sibling_hash = if (sibling_idx < level_len) level[sibling_idx] else level[idx];
            try siblings.append(.{
                .hash = sibling_hash,
                .is_left = sibling_idx < idx,
            });

            const next_len = (level_len + 1) / 2;
            var next = try self.allocator.alloc([32]u8, next_len);
            defer self.allocator.free(next);

            var i: usize = 0;
            while (i < level_len) : (i += 2) {
                const left = level[i];
                const right = if (i + 1 < level_len) level[i + 1] else level[i];
                next[i / 2] = hashPair(left, right);
            }

            @memcpy(level[0..next_len], next);
            level_len = next_len;
            idx = idx / 2;
        }

        return .{
            .leaf_index = leaf_index,
            .leaf_hash = self.leaves.items[leaf_index],
            .siblings = try siblings.toOwnedSlice(),
        };
    }
};

pub fn verifyProof(proof: MerkleProof, root: [32]u8) bool {
    var cur = proof.leaf_hash;
    for (proof.siblings) |sibling| {
        cur = if (sibling.is_left)
            hashPair(sibling.hash, cur)
        else
            hashPair(cur, sibling.hash);
    }
    return std.mem.eql(u8, &cur, &root);
}

fn hashPair(left: [32]u8, right: [32]u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&left);
    h.update(&right);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return digest;
}

fn hashEmpty() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("");
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return digest;
}
