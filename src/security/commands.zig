const std = @import("std");

pub fn isCommandSafe(cmd: []const u8) bool {
    // Scaffold implementation (tighten as you port):
    // deny obvious shell metacharacters and separators.
    const bad = [_][]const u8{ "&&", "||", ";", "|", "`", "$(", ">", "<" };
    for (bad) |b| if (std.mem.indexOf(u8, cmd, b) != null) return false;
    return true;
}
