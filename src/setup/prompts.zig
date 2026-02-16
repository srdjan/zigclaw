const std = @import("std");

pub fn readLine(io: std.Io, prompt: []const u8, buf: []u8) ![]const u8 {
    _ = buf;
    var obuf: [1024]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.writeAll(prompt);
    try ow.flush();

    var reader_buf: [1024]u8 = undefined;
    var reader = std.Io.File.stdin().reader(io, &reader_buf);
    const line = reader.interface.takeDelimiter('\n') catch |e| switch (e) {
        error.StreamTooLong => {
            _ = reader.interface.discardDelimiterInclusive('\n') catch return "";
            return "";
        },
        error.ReadFailed => return "",
    };
    if (line == null) return "";
    return std.mem.trim(u8, line.?, " \t\r\n");
}

pub fn readChoice(io: std.Io, prompt: []const u8, options: []const []const u8) !usize {
    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.print("{s}\n", .{prompt});
    for (options, 0..) |opt, i| {
        try ow.interface.print("  {d}) {s}\n", .{ i + 1, opt });
    }
    try ow.interface.writeAll("> ");
    try ow.flush();

    var reader_buf: [256]u8 = undefined;
    var reader = std.Io.File.stdin().reader(io, &reader_buf);
    const line = reader.interface.takeDelimiter('\n') catch |e| switch (e) {
        error.StreamTooLong => {
            _ = reader.interface.discardDelimiterInclusive('\n') catch return 0;
            return 0;
        },
        error.ReadFailed => return 0,
    };
    if (line == null) return 0;
    const trimmed = std.mem.trim(u8, line.?, " \t\r\n");
    const choice = std.fmt.parseInt(usize, trimmed, 10) catch return 0;
    if (choice == 0 or choice > options.len) return 0;
    return choice - 1;
}

pub fn readYesNo(io: std.Io, prompt: []const u8, default: bool) !bool {
    var obuf: [1024]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    const hint: []const u8 = if (default) " [Y/n] " else " [y/N] ";
    try ow.interface.print("{s}{s}", .{ prompt, hint });
    try ow.flush();

    var reader_buf: [256]u8 = undefined;
    var reader = std.Io.File.stdin().reader(io, &reader_buf);
    const line = reader.interface.takeDelimiter('\n') catch |e| switch (e) {
        error.StreamTooLong => {
            _ = reader.interface.discardDelimiterInclusive('\n') catch return default;
            return default;
        },
        error.ReadFailed => return default,
    };
    if (line == null) return default;
    const trimmed = std.mem.trim(u8, line.?, " \t\r\n");
    if (trimmed.len == 0) return default;
    return trimmed[0] == 'y' or trimmed[0] == 'Y';
}
