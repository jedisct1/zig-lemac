# zig-lemac

A Zig implementation of LeMac, a high-performance AES-based MAC.

## What is LeMac?

LeMac is a MAC (Message Authentication Code) that uses AES as its core primitive. It's designed to be very fast on modern CPUs with hardware AES support.

This implementation includes three variants:

- LeMac: The standard single-instance version
- LeMacX2: Processes 2 blocks in parallel using 256-bit SIMD
- LeMacX4: Processes 4 blocks in parallel using 512-bit SIMD

The parallel variants can achieve higher throughput on long messages by taking advantage of SIMD instructions.

## Usage

```zig
const LeMac = @import("lemac").LeMac;

const key: [16]u8 = ...; // Your 128-bit key
const nonce: [16]u8 = ...; // Nonce
const message: []const u8 = "Hello, world!";

// Initialize context once, reuse for multiple messages
const ctx = LeMac.init(key);

// Compute the 128-bit tag
const tag = LeMac.mac(&ctx, message, nonce);
```

The nonce can be a constant 16-byte string.

However, unique nonces offer full 128-bit security, while static nonces provide security only up to 2^64 queries.

## Building

```sh
zig build
```

To run the tests:

```sh
zig build test
```

To run a benchmark:

```sh
zig build bench
```

## Benchmark Results

AMD Zen4:

```text
Mb/s - Higher it better

           Algorithm |     64 B |    256 B |    1 KiB |    8 KiB |   64 KiB
---------------------+----------+----------+----------+----------+----------
               LeMac |    12800 |    32171 |   102518 |   310705 |   416594
            LeMac-X2 |     6910 |    31968 |   118935 |   485242 |   749384
            LeMac-X4 |     5632 |    26186 |    94315 |   450533 |   764121
---------------------+----------+----------+----------+----------+----------
      AEGIS-128L-MAC |    11985 |    40391 |    98925 |   170921 |   187968
     AEGIS-128X2-MAC |     8106 |    30595 |    98951 |   281499 |   364964
     AEGIS-128X4-MAC |     5092 |    21916 |    77374 |   289416 |   439674
---------------------+----------+----------+----------+----------+----------
         HMAC-SHA256 |     2415 |     6223 |    10293 |    12717 |    13103
```

## Reference

Based on the paper [Fast AES-Based Universal Hash Functions and MACs](https://tosc.iacr.org/index.php/ToSC/article/view/11619) published in IACR Transactions on Symmetric Cryptology, its [corrigendum](https://tosc.iacr.org/index.php/ToSC/article/view/12089), and discussions with Augustin Bariant during FSE 2025.

Original implementation: [lemac](https://github.com/jedisct1/lemac).
