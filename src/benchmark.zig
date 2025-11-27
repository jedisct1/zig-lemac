//! Benchmark comparing LeMac variants with HMAC-SHA256 and AEGIS-MAC

const std = @import("std");
const time = std.time;
const Timer = time.Timer;
const crypto = std.crypto;
const mem = std.mem;

const lemac = @import("lemac.zig");

const KiB = 1024;
const MiB = 1024 * KiB;

// Minimum time to run each benchmark (in nanoseconds)
const MIN_BENCH_TIME_NS = 500 * time.ns_per_ms; // 500ms

var prng = std.Random.DefaultPrng.init(0x12345678);
const random = prng.random();

/// Generic MAC benchmark result
const BenchResult = struct {
    throughput_mbps: f64, // megabits per second
    iterations: u64,
    total_bytes: u64,
};

/// Benchmark a MAC that follows the standard library interface (create function)
fn benchmarkStdMac(comptime Mac: type, data: []const u8) !BenchResult {
    var key: [Mac.key_length]u8 = undefined;
    random.bytes(&key);

    var mac: [Mac.mac_length]u8 = undefined;
    var iterations: u64 = 0;

    var timer = try Timer.start();
    const start = timer.lap();

    while (true) {
        Mac.create(&mac, data, &key);
        mem.doNotOptimizeAway(&mac);
        iterations += 1;

        const elapsed = timer.read() - start;
        if (elapsed >= MIN_BENCH_TIME_NS) break;
    }

    const end = timer.read();
    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const total_bytes = iterations * data.len;
    const total_bits = @as(f64, @floatFromInt(total_bytes)) * 8.0;
    const throughput_mbps = total_bits / elapsed_s / 1_000_000.0;

    return .{
        .throughput_mbps = throughput_mbps,
        .iterations = iterations,
        .total_bytes = total_bytes,
    };
}

/// Benchmark LeMac variants (different API)
fn benchmarkLeMac(comptime LeMacType: type, data: []const u8) !BenchResult {
    var key: [LeMacType.key_size]u8 = undefined;
    var nonce: [LeMacType.nonce_size]u8 = undefined;
    random.bytes(&key);
    random.bytes(&nonce);

    const ctx = LeMacType.init(key);
    var tag: [LeMacType.tag_size]u8 = undefined;
    var iterations: u64 = 0;

    var timer = try Timer.start();
    const start = timer.lap();

    while (true) {
        tag = LeMacType.mac(&ctx, data, nonce);
        mem.doNotOptimizeAway(&tag);
        iterations += 1;

        const elapsed = timer.read() - start;
        if (elapsed >= MIN_BENCH_TIME_NS) break;
    }

    const end = timer.read();
    const elapsed_s = @as(f64, @floatFromInt(end - start)) / time.ns_per_s;
    const total_bytes = iterations * data.len;
    const total_bits = @as(f64, @floatFromInt(total_bytes)) * 8.0;
    const throughput_mbps = total_bits / elapsed_s / 1_000_000.0;

    return .{
        .throughput_mbps = throughput_mbps,
        .iterations = iterations,
        .total_bytes = total_bytes,
    };
}

fn printHeader(stdout: *std.Io.Writer) !void {
    try stdout.print("\n{s:>20} | {s:>8} | {s:>8} | {s:>8} | {s:>8} | {s:>8}\n", .{
        "Algorithm",
        "64 B",
        "256 B",
        "1 KiB",
        "8 KiB",
        "64 KiB",
    });
    try stdout.flush();
    try stdout.print("{s:->21}+{s:->10}+{s:->10}+{s:->10}+{s:->10}+{s:->10}\n", .{
        "", "", "", "", "", "",
    });
    try stdout.flush();
}

fn formatThroughput(throughput: f64) [8]u8 {
    var buf: [8]u8 = .{' '} ** 8;
    _ = std.fmt.bufPrint(&buf, "{d:>8.0}", .{throughput}) catch unreachable;
    return buf;
}

fn runBenchSuite(
    stdout: *std.Io.Writer,
    name: []const u8,
    benchFn: anytype,
    data_64: []const u8,
    data_256: []const u8,
    data_1k: []const u8,
    data_8k: []const u8,
    data_64k: []const u8,
) !void {
    const r64 = try benchFn(data_64);
    const r256 = try benchFn(data_256);
    const r1k = try benchFn(data_1k);
    const r8k = try benchFn(data_8k);
    const r64k = try benchFn(data_64k);

    try stdout.print("{s:>20} | {s} | {s} | {s} | {s} | {s}\n", .{
        name,
        formatThroughput(r64.throughput_mbps),
        formatThroughput(r256.throughput_mbps),
        formatThroughput(r1k.throughput_mbps),
        formatThroughput(r8k.throughput_mbps),
        formatThroughput(r64k.throughput_mbps),
    });
    try stdout.flush();
}

pub fn main() !void {
    var stdout_buffer: [0x200]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("MAC Benchmark - Throughput in Mb/s (higher is better)\n", .{});
    try stdout.flush();
    try stdout.print("Min benchmark time: {d}ms per size\n", .{MIN_BENCH_TIME_NS / time.ns_per_ms});
    try stdout.flush();

    // Allocate test data
    var data_64: [64]u8 = undefined;
    var data_256: [256]u8 = undefined;
    var data_1k: [1 * KiB]u8 = undefined;
    var data_8k: [8 * KiB]u8 = undefined;
    var data_64k: [64 * KiB]u8 = undefined;

    random.bytes(&data_64);
    random.bytes(&data_256);
    random.bytes(&data_1k);
    random.bytes(&data_8k);
    random.bytes(&data_64k);

    // Print header
    try printHeader(stdout);

    // LeMac variants
    try runBenchSuite(
        stdout,
        "LeMac",
        struct {
            fn bench(data: []const u8) !BenchResult {
                return benchmarkLeMac(lemac.LeMac, data);
            }
        }.bench,
        &data_64,
        &data_256,
        &data_1k,
        &data_8k,
        &data_64k,
    );

    try runBenchSuite(
        stdout,
        "LeMac-X2",
        struct {
            fn bench(data: []const u8) !BenchResult {
                return benchmarkLeMac(lemac.LeMacX2, data);
            }
        }.bench,
        &data_64,
        &data_256,
        &data_1k,
        &data_8k,
        &data_64k,
    );

    try runBenchSuite(
        stdout,
        "LeMac-X4",
        struct {
            fn bench(data: []const u8) !BenchResult {
                return benchmarkLeMac(lemac.LeMacX4, data);
            }
        }.bench,
        &data_64,
        &data_256,
        &data_1k,
        &data_8k,
        &data_64k,
    );

    // Separator
    try stdout.print("{s:->21}+{s:->10}+{s:->10}+{s:->10}+{s:->10}+{s:->10}\n", .{
        "", "", "", "", "", "",
    });
    try stdout.flush();

    // AEGIS-MAC variants
    try runBenchSuite(
        stdout,
        "AEGIS-128L-MAC",
        struct {
            fn bench(data: []const u8) !BenchResult {
                return benchmarkStdMac(crypto.auth.aegis.Aegis128LMac, data);
            }
        }.bench,
        &data_64,
        &data_256,
        &data_1k,
        &data_8k,
        &data_64k,
    );

    try runBenchSuite(
        stdout,
        "AEGIS-128X2-MAC",
        struct {
            fn bench(data: []const u8) !BenchResult {
                return benchmarkStdMac(crypto.auth.aegis.Aegis128X2Mac, data);
            }
        }.bench,
        &data_64,
        &data_256,
        &data_1k,
        &data_8k,
        &data_64k,
    );

    try runBenchSuite(
        stdout,
        "AEGIS-128X4-MAC",
        struct {
            fn bench(data: []const u8) !BenchResult {
                return benchmarkStdMac(crypto.auth.aegis.Aegis128X4Mac, data);
            }
        }.bench,
        &data_64,
        &data_256,
        &data_1k,
        &data_8k,
        &data_64k,
    );

    // Separator
    try stdout.print("{s:->21}+{s:->10}+{s:->10}+{s:->10}+{s:->10}+{s:->10}\n", .{
        "", "", "", "", "", "",
    });
    try stdout.flush();

    // HMAC-SHA256
    try runBenchSuite(
        stdout,
        "HMAC-SHA256",
        struct {
            fn bench(data: []const u8) !BenchResult {
                return benchmarkStdMac(crypto.auth.hmac.sha2.HmacSha256, data);
            }
        }.bench,
        &data_64,
        &data_256,
        &data_1k,
        &data_8k,
        &data_64k,
    );

    try stdout.print("\n", .{});
    try stdout.flush();
}
