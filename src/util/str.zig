/// String utilities shared across the codebase.
/// Includes Levenshtein distance for "did you mean?" suggestions.

pub fn levenshtein(a_str: []const u8, b_str: []const u8) usize {
    if (a_str.len == 0) return b_str.len;
    if (b_str.len == 0) return a_str.len;
    if (b_str.len > 64) return b_str.len; // bail on long strings

    var prev_row: [65]usize = undefined;
    for (0..b_str.len + 1) |i| prev_row[i] = i;

    for (a_str, 0..) |a_ch, i| {
        var cur_row: [65]usize = undefined;
        cur_row[0] = i + 1;
        for (b_str, 0..) |b_ch, j| {
            const cost: usize = if (a_ch == b_ch) 0 else 1;
            cur_row[j + 1] = @min(@min(
                cur_row[j] + 1,
                prev_row[j + 1] + 1,
            ), prev_row[j] + cost);
        }
        prev_row = cur_row;
    }
    return prev_row[b_str.len];
}

/// Returns the closest match from `candidates` if the distance is <= `max_dist`.
/// Returns null if no candidate is close enough.
pub fn closestMatch(needle: []const u8, candidates: []const []const u8, max_dist: usize) ?[]const u8 {
    var best: ?[]const u8 = null;
    var best_dist: usize = max_dist + 1;
    for (candidates) |c| {
        const d = levenshtein(needle, c);
        if (d < best_dist) {
            best_dist = d;
            best = c;
        }
    }
    return best;
}
