const std = @import("std");
const builtin = @import("builtin");

pub fn platformKey() ?[]const u8 {
    return switch (builtin.os.tag) {
        .linux => switch (builtin.cpu.arch) {
            .x86_64 => "x86_64-linux-musl",
            .aarch64 => "aarch64-linux-musl",
            else => null,
        },
        .macos => switch (builtin.cpu.arch) {
            .x86_64 => "x86_64-macos",
            .aarch64 => "aarch64-macos",
            else => null,
        },
        else => null,
    };
}
