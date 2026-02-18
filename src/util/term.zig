const std = @import("std");

pub const Style = enum {
    red,
    green,
    yellow,
    bold,
    reset,

    pub fn code(self: Style) []const u8 {
        return switch (self) {
            .red => "\x1b[31m",
            .green => "\x1b[32m",
            .yellow => "\x1b[33m",
            .bold => "\x1b[1m",
            .reset => "\x1b[0m",
        };
    }
};

/// Returns true if the given fd is a TTY and NO_COLOR is not set.
fn supportsColor(fd: c_int) bool {
    if (std.c.getenv("NO_COLOR") != null) return false;
    return std.c.isatty(fd) != 0;
}

pub fn stdoutSupportsColor() bool {
    return supportsColor(1);
}

pub fn stderrSupportsColor() bool {
    return supportsColor(2);
}

pub fn stdinIsTty() bool {
    return std.c.isatty(0) != 0;
}

/// Write styled text: if color is enabled, wraps content in ANSI codes.
pub fn writeStyled(writer: anytype, style: Style, text: []const u8, color_enabled: bool) !void {
    if (color_enabled) {
        try writer.writeAll(style.code());
        try writer.writeAll(text);
        try writer.writeAll(Style.reset.code());
    } else {
        try writer.writeAll(text);
    }
}
