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

    // --- WASI plugin: fs_write
    const plugin_fs_write = b.addExecutable(.{
        .name = "fs_write.wasm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("plugins/fs_write/src/main.zig"),
            .target = wasi_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "plugin_sdk", .module = sdk_mod },
            },
        }),
    });
    b.installArtifact(plugin_fs_write);

    // --- Native plugins (compiled for host target)
    const native_sdk_mod = b.createModule(.{
        .root_source_file = b.path("plugins/sdk/protocol.zig"),
    });

    const plugin_shell_exec = b.addExecutable(.{
        .name = "shell_exec",
        .root_module = b.createModule(.{
            .root_source_file = b.path("plugins/shell_exec/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "plugin_sdk", .module = native_sdk_mod },
            },
        }),
    });
    b.installArtifact(plugin_shell_exec);

    const plugin_http_fetch = b.addExecutable(.{
        .name = "http_fetch",
        .root_module = b.createModule(.{
            .root_source_file = b.path("plugins/http_fetch/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "plugin_sdk", .module = native_sdk_mod },
            },
        }),
    });
    b.installArtifact(plugin_http_fetch);

    // Install manifests next to the binaries in zig-out/bin
    const install_echo_manifest = b.addInstallFileWithDir(b.path("plugins/echo/tool.toml"), .bin, "echo.toml");
    const install_fs_read_manifest = b.addInstallFileWithDir(b.path("plugins/fs_read/tool.toml"), .bin, "fs_read.toml");
    const install_fs_write_manifest = b.addInstallFileWithDir(b.path("plugins/fs_write/tool.toml"), .bin, "fs_write.toml");
    const install_shell_exec_manifest = b.addInstallFileWithDir(b.path("plugins/shell_exec/tool.toml"), .bin, "shell_exec.toml");
    const install_http_fetch_manifest = b.addInstallFileWithDir(b.path("plugins/http_fetch/tool.toml"), .bin, "http_fetch.toml");

    const s1 = b.step("plugin-echo", "Build/install echo WASI plugin + manifest");
    s1.dependOn(&plugin_echo.step);
    s1.dependOn(&install_echo_manifest.step);

    const s2 = b.step("plugin-fs_read", "Build/install fs_read WASI plugin + manifest");
    s2.dependOn(&plugin_fs_read.step);
    s2.dependOn(&install_fs_read_manifest.step);

    const s3 = b.step("plugin-fs_write", "Build/install fs_write WASI plugin + manifest");
    s3.dependOn(&plugin_fs_write.step);
    s3.dependOn(&install_fs_write_manifest.step);

    const s4 = b.step("plugin-shell_exec", "Build/install shell_exec native plugin + manifest");
    s4.dependOn(&plugin_shell_exec.step);
    s4.dependOn(&install_shell_exec_manifest.step);

    const s5 = b.step("plugin-http_fetch", "Build/install http_fetch native plugin + manifest");
    s5.dependOn(&plugin_http_fetch.step);
    s5.dependOn(&install_http_fetch_manifest.step);

    const s_all = b.step("plugins", "Build/install all plugins + manifests");
    s_all.dependOn(s1);
    s_all.dependOn(s2);
    s_all.dependOn(s3);
    s_all.dependOn(s4);
    s_all.dependOn(s5);
}
