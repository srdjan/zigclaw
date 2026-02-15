const std = @import("std");
const provider = @import("provider.zig");

pub const ReliableProvider = struct {
    inner: *provider.Provider,
    retries: u32,
    base_backoff_ms: u32,

    pub fn init(inner: *provider.Provider, retries: u32, backoff_ms: u32) ReliableProvider {
        return .{ .inner = inner, .retries = retries, .base_backoff_ms = backoff_ms };
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

                // Permanent errors: do not retry
                if (isPermanentError(err)) return err;

                // Exponential backoff with jitter:
                // delay = base_ms * 2^attempt + random jitter [0, base_ms)
                const exp: u6 = @intCast(@min(attempt, 5)); // cap exponent to avoid overflow
                const backoff: u64 = @as(u64, self.base_backoff_ms) * (@as(u64, 1) << exp);
                const jitter = jitterMs(io, self.base_backoff_ms);
                const delay = backoff + jitter;

                io.sleep(std.Io.Duration.fromMilliseconds(@intCast(delay)), .awake) catch {};
                continue;
            }
        }
    }
};

/// Errors that should not be retried (auth failures, invalid requests, etc.)
fn isPermanentError(err: anyerror) bool {
    return switch (err) {
        error.ToolNotAllowed,
        error.InvalidToolArgs,
        error.ToolNetworkNotAllowed,
        error.InvalidJson,
        error.InvalidResponse,
        => true,
        else => false,
    };
}

/// Generate a pseudo-random jitter value in [0, max_ms) using the system clock.
/// Not cryptographically secure - just enough for backoff decorrelation.
fn jitterMs(io: std.Io, max_ms: u32) u64 {
    if (max_ms == 0) return 0;
    const ts = std.Io.Clock.now(.real, io);
    // Use the low-order nanoseconds as a cheap entropy source
    const ns: u64 = @intCast(@mod(ts.nanoseconds, std.time.ns_per_s));
    return ns % max_ms;
}
