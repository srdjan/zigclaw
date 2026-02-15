const std = @import("std");

pub const MemoryItem = struct {
    title: []u8,
    snippet: []u8,
    score: f32,
};

pub fn empty(a: std.mem.Allocator) ![]MemoryItem {
    return try a.dupe(MemoryItem, &.{});
}

/// Very small scorer:
/// - splits into paragraphs
/// - counts query token occurrences
/// - returns top-N snippets
pub fn scoreMarkdown(a: std.mem.Allocator, md: []const u8, query: []const u8, limit: usize) ![]MemoryItem {
    var tokens = std.array_list.Managed([]const u8).init(a);
    defer tokens.deinit();

    // tokenize query by whitespace
    var qit = std.mem.splitAny(u8, query, " \t\r\n");
    while (qit.next()) |t| {
        const tt = std.mem.trim(u8, t, " \t\r\n");
        if (tt.len > 0) try tokens.append(tt);
    }

    var items = std.array_list.Managed(MemoryItem).init(a);
    errdefer {
        for (items.items) |it| { a.free(it.title); a.free(it.snippet); }
        items.deinit();
    }

    var pit = std.mem.splitSequence(u8, md, "\n\n");
    while (pit.next()) |para0| {
        const para = std.mem.trim(u8, para0, " \t\r\n");
        if (para.len == 0) continue;

        var score: f32 = 0;
        for (tokens.items) |tok| {
            score += @floatFromInt(countOccur(para, tok));
        }
        if (score == 0) continue;

        const snip = try a.dupe(u8, truncate(para, 200));
        const title = try a.dupe(u8, "memory");
        try items.append(.{ .title = title, .snippet = snip, .score = score });
    }

    // partial sort: selection top N
    const n = @min(limit, items.items.len);
    for (0..n) |i| {
        var best = i;
        for (i..items.items.len) |j| {
            if (items.items[j].score > items.items[best].score) best = j;
        }
        if (best != i) {
            const tmp = items.items[i];
            items.items[i] = items.items[best];
            items.items[best] = tmp;
        }
    }

    // trim
    while (items.items.len > n) {
        const itrm = items.pop().?;
        a.free(itrm.title);
        a.free(itrm.snippet);
    }

    return try items.toOwnedSlice();
}

fn countOccur(hay: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;
    var count: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.mem.eql(u8, hay[i .. i + needle.len], needle)) count += 1;
    }
    return count;
}

fn truncate(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    return s[0..max];
}
