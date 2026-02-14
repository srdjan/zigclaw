const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- Native executable
    const exe = b.addExecutable(.{
        .name = "zigclaw",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    // Run step: `zig build run -- <args>`
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zigclaw");
    run_step.dependOn(&run_cmd.step);

    // --- Tests
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // --- WASI plugins (compiled as wasm32-wasi)
    const wasi_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .wasi,
    });

    // Shared plugin SDK module
    const sdk_mod = b.createModule(.{
        .root_source_file = b.path("plugins/sdk/protocol.zig"),
    });

    // Build to names with .wasm extension so ToolRunner can locate them easily.
    const plugin_echo = b.addExecutable(.{
        .name = "echo.wasm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("plugins/echo/src/main.zig"),
            .target = wasi_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "plugin_sdk", .module = sdk_mod },
            },
        }),
    });
    b.installArtifact(plugin_echo);

    const plugin_fs_read = b.addExecutable(.{
        .name = "fs_read.wasm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("plugins/fs_read/src/main.zig"),
            .target = wasi_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "plugin_sdk", .module = sdk_mod },
            },
        }),
    });
    b.installArtifact(plugin_fs_read);

    // Install manifests next to the wasm binaries in zig-out/bin
    const install_echo_manifest = b.addInstallFileWithDir(b.path("plugins/echo/tool.toml"), .bin, "echo.toml");
    const install_fs_read_manifest = b.addInstallFileWithDir(b.path("plugins/fs_read/tool.toml"), .bin, "fs_read.toml");

    const s1 = b.step("plugin-echo", "Build/install echo WASI plugin + manifest to zig-out/bin");
    s1.dependOn(&plugin_echo.step);
    s1.dependOn(&install_echo_manifest.step);

    const s2 = b.step("plugin-fs_read", "Build/install fs_read WASI plugin + manifest to zig-out/bin");
    s2.dependOn(&plugin_fs_read.step);
    s2.dependOn(&install_fs_read_manifest.step);

    const s_all = b.step("plugins", "Build/install all WASI plugins + manifests");
    s_all.dependOn(s1);
    s_all.dependOn(s2);
}
