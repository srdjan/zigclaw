const std = @import("std");

const version = "0.2.0";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const host = b.graph.host;

    // Build options module (version string available at comptime)
    const options = b.addOptions();
    options.addOption([]const u8, "version", version);

    // Generate compile-time tool registry from plugin manifests.
    const registry_gen = b.addExecutable(.{
        .name = "zigclaw_registry_gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/registry_gen.zig"),
            .target = host,
            .optimize = optimize,
        }),
    });
    const run_registry_gen = b.addRunArtifact(registry_gen);
    run_registry_gen.addArgs(&.{
        "--plugin-dir",
        "plugins",
        "--out",
        "src/tools/registry_generated.zig",
    });

    const registry_step = b.step("registry", "Generate src/tools/registry_generated.zig");
    registry_step.dependOn(&run_registry_gen.step);

    // --- Native executable
    const exe = b.addExecutable(.{
        .name = "zigclaw",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addOptions("build_options", options);
    exe.step.dependOn(&run_registry_gen.step);
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
    tests.root_module.addOptions("build_options", options);
    tests.step.dependOn(&run_registry_gen.step);
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

    // --- Release cross-compilation targets
    const release_step = b.step("release", "Cross-compile release binaries for all platforms");

    const release_targets = [_]struct {
        query: std.Target.Query,
        name: []const u8,
    }{
        .{ .query = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl }, .name = "x86_64-linux-musl" },
        .{ .query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl }, .name = "aarch64-linux-musl" },
        .{ .query = .{ .cpu_arch = .x86_64, .os_tag = .macos }, .name = "x86_64-macos" },
        .{ .query = .{ .cpu_arch = .aarch64, .os_tag = .macos }, .name = "aarch64-macos" },
    };

    // WASI plugins are target-independent: build once
    const wasi_release_sdk = b.createModule(.{
        .root_source_file = b.path("plugins/sdk/protocol.zig"),
    });

    const wasi_plugins = [_]struct { name: []const u8, src: []const u8 }{
        .{ .name = "echo.wasm", .src = "plugins/echo/src/main.zig" },
        .{ .name = "fs_read.wasm", .src = "plugins/fs_read/src/main.zig" },
        .{ .name = "fs_write.wasm", .src = "plugins/fs_write/src/main.zig" },
    };

    for (wasi_plugins) |wp| {
        const wasi_exe = b.addExecutable(.{
            .name = wp.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(wp.src),
                .target = wasi_target,
                .optimize = .ReleaseSafe,
                .imports = &.{
                    .{ .name = "plugin_sdk", .module = wasi_release_sdk },
                },
            }),
        });
        const install_wasi = b.addInstallArtifact(wasi_exe, .{
            .dest_dir = .{ .override = .{ .custom = "release/wasi" } },
        });
        release_step.dependOn(&install_wasi.step);
    }

    // Per-target: zigclaw exe + native plugins
    for (release_targets) |rt| {
        const resolved = b.resolveTargetQuery(rt.query);

        const rel_exe = b.addExecutable(.{
            .name = "zigclaw",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = resolved,
                .optimize = .ReleaseSafe,
            }),
        });
        rel_exe.root_module.addOptions("build_options", options);
        rel_exe.step.dependOn(&run_registry_gen.step);
        const install_exe = b.addInstallArtifact(rel_exe, .{
            .dest_dir = .{ .override = .{ .custom = b.fmt("release/{s}", .{rt.name}) } },
        });
        release_step.dependOn(&install_exe.step);

        // Native plugins for this target
        const rel_native_sdk = b.createModule(.{
            .root_source_file = b.path("plugins/sdk/protocol.zig"),
        });

        const native_plugins = [_]struct { name: []const u8, src: []const u8 }{
            .{ .name = "shell_exec", .src = "plugins/shell_exec/src/main.zig" },
            .{ .name = "http_fetch", .src = "plugins/http_fetch/src/main.zig" },
        };

        for (native_plugins) |np| {
            const rel_plugin = b.addExecutable(.{
                .name = np.name,
                .root_module = b.createModule(.{
                    .root_source_file = b.path(np.src),
                    .target = resolved,
                    .optimize = .ReleaseSafe,
                    .imports = &.{
                        .{ .name = "plugin_sdk", .module = rel_native_sdk },
                    },
                }),
            });
            const install_plugin = b.addInstallArtifact(rel_plugin, .{
                .dest_dir = .{ .override = .{ .custom = b.fmt("release/{s}", .{rt.name}) } },
            });
            release_step.dependOn(&install_plugin.step);
        }
    }
}
