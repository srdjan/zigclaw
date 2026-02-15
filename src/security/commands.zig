const std = @import("std");

/// Validate that a command string contains no shell metacharacters or
/// injection vectors.
///
/// This uses an allowlist approach: every byte must be in the set of
/// safe characters. Any byte outside the set causes rejection.
/// This is strictly more secure than the previous denylist approach
/// because unknown/novel injection vectors are rejected by default.
///
/// Safe characters: alphanumeric, '.', '_', '/', '-', ' ', ':', '=', ','
/// These cover typical command invocations like "wasmtime run --mapdir /a=/b"
/// without permitting shell metacharacters.
pub fn isCommandSafe(cmd: []const u8) bool {
    if (cmd.len == 0) return false;

    for (cmd) |c| {
        if (!isSafeCommandByte(c)) return false;
    }
    return true;
}

fn isSafeCommandByte(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '.', '_', '/', '-', ' ', ':', '=', ',' => true,
        else => false,
    };
}
