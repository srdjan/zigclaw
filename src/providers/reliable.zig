const std = @import("std");
const provider = @import("provider.zig");

pub const ReliableProvider = struct {
    inner: *provider.Provider,
    retries: u32,
    backoff_ms: u32,

    pub fn init(inner: *provider.Provider, retries: u32, backoff_ms: u32) ReliableProvider {
        return .{ .inner = inner, .retries = retries, .backoff_ms = backoff_ms };
    }

    pub fn deinit(self: *ReliableProvider, a: std.mem.Allocator) void {
        self.inner.deinit(a);
        a.destroy(self.inner);
    }

    pub fn chat(self: ReliableProvider, a: std.mem.Allocator, io: std.Io, req: provider.ChatRequest) !provider.ChatResponse {
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            const res = self.inner.chat(a, io, req);
            if (res) |ok| return ok else |err| {
                if (attempt >= self.retries) return err;
                // deterministic backoff
                io.sleep(std.Io.Duration.fromMilliseconds(@intCast(self.backoff_ms)), .awake) catch {};
                continue;
            }
        }
    }
};
