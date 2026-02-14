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

    pub fn chat(self: ReliableProvider, a: std.mem.Allocator, req: provider.ChatRequest) !provider.ChatResponse {
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            const res = self.inner.chat(a, req);
            if (res) |ok| return ok else |err| {
                if (attempt >= self.retries) return err;
                // deterministic backoff
                std.time.sleep(@as(u64, self.backoff_ms) * std.time.ns_per_ms);
                continue;
            }
        }
    }
};
