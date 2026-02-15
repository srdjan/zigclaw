const std = @import("std");

pub fn diffTextAlloc(a: std.mem.Allocator, left: []const u8, right: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();

    var la = std.mem.splitScalar(u8, left, '\n');
    var lb = std.mem.splitScalar(u8, right, '\n');

    while (true) {
        const a_line = la.next();
        const b_line = lb.next();
        if (a_line == null and b_line == null) break;

        if (a_line != null and b_line != null) {
            const al = a_line.?;
            const bl = b_line.?;
            if (std.mem.eql(u8, al, bl)) {
                try aw.writer.print(" {s}\n", .{al});
            } else {
                try aw.writer.print("-{s}\n", .{al});
                try aw.writer.print("+{s}\n", .{bl});
            }
            continue;
        }
        if (a_line != null) {
            try aw.writer.print("-{s}\n", .{a_line.?});
        } else {
            try aw.writer.print("+{s}\n", .{b_line.?});
        }
    }

    return try aw.toOwnedSlice();
}
