const std = @import("std");

pub fn readLine(io: std.Io, prompt: []const u8, buf: []u8) ![]const u8 {
    try printPrompt(io, prompt);
    return readInputLine(io, buf);
}

pub fn readSecretLine(io: std.Io, prompt: []const u8, buf: []u8) ![]const u8 {
    try printPrompt(io, prompt);
    setTerminalEcho(io, false);
    defer setTerminalEcho(io, true);

    const out = try readInputLine(io, buf);

    // Move to a new line because hidden input won't echo newline consistently.
    var obuf: [128]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.writeAll("\n");
    try ow.flush();
    return out;
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

fn printPrompt(io: std.Io, prompt: []const u8) !void {
    var obuf: [1024]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    try ow.interface.writeAll(prompt);
    try ow.flush();
}

fn readInputLine(io: std.Io, buf: []u8) ![]const u8 {
    var reader_buf: [1024]u8 = undefined;
    var reader = std.Io.File.stdin().reader(io, &reader_buf);
    const line = reader.interface.takeDelimiter('\n') catch |e| switch (e) {
        error.StreamTooLong => {
            _ = reader.interface.discardDelimiterInclusive('\n') catch return buf[0..0];
            return buf[0..0];
        },
        error.ReadFailed => return buf[0..0],
    };
    if (line == null) return buf[0..0];
    const trimmed = std.mem.trim(u8, line.?, " \t\r\n");
    if (trimmed.len == 0) return buf[0..0];
    if (trimmed.len > buf.len) return buf[0..0];
    @memcpy(buf[0..trimmed.len], trimmed);
    return buf[0..trimmed.len];
}

fn setTerminalEcho(io: std.Io, enabled: bool) void {
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) return;

    const cmd = if (enabled) "stty echo < /dev/tty" else "stty -echo < /dev/tty";
    const argv = [_][]const u8{ "/bin/sh", "-c", cmd };
    var child = std.process.spawn(io, .{
        .argv = &argv,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch return;
    _ = child.wait(io) catch {};
}
