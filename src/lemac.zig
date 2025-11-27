//! LeMac, LeMAC-X2, and LeMAC-X4 implementation
//!
//! LeMac is a fast AES-based MAC.
//! LeMAC-X2 and LeMAC-X4 are parallel variants using SIMD for higher throughput.
//!
//! Reference: "Fast AES-Based Universal Hash Functions and MACs"
//! https://tosc.iacr.org/index.php/ToSC/article/view/11619

const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const Aes128 = aes.Aes128;
const Block = aes.Block;

/// Generic LeMac implementation supporting parallelization.
/// - degree=1: Standard LeMac (128-bit blocks)
/// - degree=2: LeMAC-X2 (256-bit vectors, 2 parallel instances)
/// - degree=4: LeMAC-X4 (512-bit vectors, 4 parallel instances)
pub fn LeMacGeneric(comptime degree: comptime_int) type {
    return struct {
        const Self = @This();

        /// Number of parallel instances
        pub const parallelism = degree;

        /// Block type for this degree (handles SIMD internally)
        const BlockType = if (degree == 1) Block else aes.BlockVec(degree);

        /// Block size in bytes for message processing
        pub const block_size = 64 * degree;

        /// Key size in bytes
        pub const key_size = 16;

        /// Nonce size in bytes
        pub const nonce_size = 16;

        /// Tag size in bytes
        pub const tag_size = 16;

        /// State: 9 blocks
        const State = [9]BlockType;

        const Aes128EncCtx = aes.AesEncryptCtx(Aes128);

        /// Context for LeMac
        pub const Context = struct {
            init_state: State,
            subkeys: [18]BlockType,
            nonce_key: Aes128EncCtx,
            finalize_key: Aes128EncCtx,
        };

        /// Initialize the context with a key
        pub fn init(key: [key_size]u8) Context {
            const aes_ctx = Aes128.initEnc(key);

            var ctx: Context = undefined;

            if (degree == 1) {
                var k_init: [9][16]u8 = undefined;
                for (&k_init, 0..) |*a, i| {
                    mem.writeInt(u128, a, i, .little);
                }
                var k_final: [18][16]u8 = undefined;
                for (&k_final, 9..) |*a, i| {
                    mem.writeInt(u128, a, i, .little);
                }
                var k2_k3: [2][16]u8 = undefined;
                mem.writeInt(u128, &k2_k3[0], 27, .little);
                mem.writeInt(u128, &k2_k3[1], 28, .little);

                aes_ctx.encryptWide(9, @ptrCast(&k_init), @ptrCast(&k_init));
                aes_ctx.encryptWide(18, @ptrCast(&k_final), @ptrCast(&k_final));
                aes_ctx.encryptWide(2, @ptrCast(&k2_k3), @ptrCast(&k2_k3));

                for (&ctx.init_state, k_init) |*state, bytes| {
                    state.* = Block.fromBytes(&bytes);
                }
                for (&ctx.subkeys, k_final) |*subkey, bytes| {
                    subkey.* = Block.fromBytes(&bytes);
                }
                ctx.nonce_key = Aes128.initEnc(k2_k3[0]);
                ctx.finalize_key = Aes128.initEnc(k2_k3[1]);
            } else {
                var k_init: [9 * degree][16]u8 = undefined;
                for (0..9) |i| {
                    inline for (0..degree) |lane| {
                        k_init[i * degree + lane] = makeConstantWithMask(i, lane, degree);
                    }
                }
                var k_final: [18 * degree][16]u8 = undefined;
                for (0..18) |i| {
                    inline for (0..degree) |lane| {
                        k_final[i * degree + lane] = makeConstantWithMask(i + 9, lane, degree);
                    }
                }
                var k2_k3: [2][16]u8 = undefined;
                mem.writeInt(u128, &k2_k3[0], 27, .little);
                mem.writeInt(u128, &k2_k3[1], 28, .little);

                aes_ctx.encryptWide(9 * degree, @ptrCast(&k_init), @ptrCast(&k_init));
                aes_ctx.encryptWide(18 * degree, @ptrCast(&k_final), @ptrCast(&k_final));
                aes_ctx.encryptWide(2, @ptrCast(&k2_k3), @ptrCast(&k2_k3));

                for (0..9) |i| {
                    var bytes: [16 * degree]u8 = undefined;
                    inline for (0..degree) |lane| {
                        @memcpy(bytes[lane * 16 ..][0..16], &k_init[i * degree + lane]);
                    }
                    ctx.init_state[i] = BlockType.fromBytes(&bytes);
                }
                for (0..18) |i| {
                    var bytes: [16 * degree]u8 = undefined;
                    inline for (0..degree) |lane| {
                        @memcpy(bytes[lane * 16 ..][0..16], &k_final[i * degree + lane]);
                    }
                    ctx.subkeys[i] = BlockType.fromBytes(&bytes);
                }
                ctx.nonce_key = Aes128.initEnc(k2_k3[0]);
                ctx.finalize_key = Aes128.initEnc(k2_k3[1]);
            }

            return ctx;
        }

        /// Compute MAC for a message
        pub fn mac(ctx: *const Context, msg: []const u8, nonce: [nonce_size]u8) [tag_size]u8 {
            const final_state = absorb(ctx, msg);
            return finalize(ctx, &final_state, nonce);
        }

        fn makeConstantWithMask(i: usize, lane: usize, comptime lanes: usize) [16]u8 {
            var constant: [16]u8 = @splat(0);
            mem.writeInt(u64, constant[0..8], @intCast(i), .little);
            constant[15] = @intCast(lanes - 1);
            constant[14] = @intCast(lane);
            return constant;
        }

        fn zeroBlock() BlockType {
            if (degree == 1) {
                return Block.fromBytes(&@as([16]u8, @splat(0)));
            } else {
                return BlockType.fromBytes(&@as([16 * degree]u8, @splat(0)));
            }
        }

        /// Load message blocks
        fn loadMessageBlock(data: []const u8) BlockType {
            if (degree == 1) {
                var buf: [16]u8 = @splat(0);
                const len = @min(data.len, 16);
                @memcpy(buf[0..len], data[0..len]);
                return Block.fromBytes(&buf);
            } else {
                var buf: [16 * degree]u8 = @splat(0);
                const len = @min(data.len, 16 * degree);
                @memcpy(buf[0..len], data[0..len]);
                return BlockType.fromBytes(&buf);
            }
        }

        /// AES round (encrypt without final round transformation)
        fn aesRound(block: BlockType, round_key: BlockType) BlockType {
            return block.encrypt(round_key);
        }

        /// Apply the round function to the state
        fn round(
            state: *State,
            rr: *BlockType,
            r0: *BlockType,
            r1: *BlockType,
            r2: *BlockType,
            m0: BlockType,
            m1: BlockType,
            m2: BlockType,
            m3: BlockType,
        ) void {
            const t = state[8];

            state[8] = aesRound(state[7], m3);
            state[7] = aesRound(state[6], m1);
            state[6] = aesRound(state[5], m1);
            state[5] = aesRound(state[4], m0);
            state[4] = aesRound(state[3], m0);
            state[3] = aesRound(state[2], r1.xorBlocks(r2.*));
            state[2] = aesRound(state[1], m3);
            state[1] = aesRound(state[0], m3);
            state[0] = state[0].xorBlocks(t).xorBlocks(m2);

            r2.* = r1.*;
            r1.* = r0.*;
            r0.* = rr.xorBlocks(m1);
            rr.* = m2;
        }

        /// Absorb the message into the state
        fn absorb(ctx: *const Context, msg: []const u8) State {
            var state = ctx.init_state;
            var rr = zeroBlock();
            var r0 = zeroBlock();
            var r1 = zeroBlock();
            var r2 = zeroBlock();

            // Process complete blocks
            const msg_block_size = 64 * degree;
            var offset: usize = 0;

            while (offset + msg_block_size <= msg.len) {
                const m0 = loadMessageBlock(msg[offset..][0 .. 16 * degree]);
                const m1 = loadMessageBlock(msg[offset + 16 * degree ..][0 .. 16 * degree]);
                const m2 = loadMessageBlock(msg[offset + 32 * degree ..][0 .. 16 * degree]);
                const m3 = loadMessageBlock(msg[offset + 48 * degree ..][0 .. 16 * degree]);

                round(&state, &rr, &r0, &r1, &r2, m0, m1, m2, m3);
                offset += msg_block_size;
            }

            // Padding: append 0x01 followed by zeros
            var padded: [64 * degree]u8 = @splat(0);
            const remaining = msg.len - offset;
            if (remaining > 0) {
                @memcpy(padded[0..remaining], msg[offset..]);
            }
            padded[remaining] = 0x01;

            const m0 = loadMessageBlock(padded[0 .. 16 * degree]);
            const m1 = loadMessageBlock(padded[16 * degree .. 32 * degree]);
            const m2 = loadMessageBlock(padded[32 * degree .. 48 * degree]);
            const m3 = loadMessageBlock(padded[48 * degree .. 64 * degree]);
            round(&state, &rr, &r0, &r1, &r2, m0, m1, m2, m3);

            // Four final rounds with zero message blocks
            const zero = zeroBlock();
            round(&state, &rr, &r0, &r1, &r2, zero, zero, zero, zero);
            round(&state, &rr, &r0, &r1, &r2, zero, zero, zero, zero);
            round(&state, &rr, &r0, &r1, &r2, zero, zero, zero, zero);
            round(&state, &rr, &r0, &r1, &r2, zero, zero, zero, zero);

            return state;
        }

        /// Modified AES: 10 rounds but last round XORs with zero key
        fn aesModified(subkeys: []const BlockType, block: BlockType) BlockType {
            var t = block.xorBlocks(subkeys[0]);
            inline for (1..10) |i| {
                t = t.encrypt(subkeys[i]);
            }
            // Final round with zero key (just the round function)
            return t.encrypt(zeroBlock());
        }

        /// Finalize and produce the tag
        fn finalize(ctx: *const Context, state: *const State, nonce: [nonce_size]u8) [tag_size]u8 {
            // Compute contribution from each state block using modified AES
            var t = aesModified(ctx.subkeys[0..10], state[0]);
            inline for (1..9) |i| {
                t = t.xorBlocks(aesModified(ctx.subkeys[i .. i + 10], state[i]));
            }

            // For X2/X4: XOR all lanes together
            var t_128: [16]u8 = undefined;
            if (degree == 1) {
                t_128 = t.toBytes();
            } else {
                const t_bytes = t.toBytes();
                t_128 = t_bytes[0..16].*;
                inline for (1..degree) |lane| {
                    const lane_bytes = t_bytes[lane * 16 ..][0..16];
                    for (0..16) |j| {
                        t_128[j] ^= lane_bytes[j];
                    }
                }
            }

            // Add nonce contribution: N XOR AES(k2, N)
            var nonce_enc: [16]u8 = undefined;
            ctx.nonce_key.encrypt(&nonce_enc, &nonce);
            for (0..16) |i| {
                t_128[i] ^= nonce[i] ^ nonce_enc[i];
            }

            // Final encryption: AES(k3, T)
            var tag: [16]u8 = undefined;
            ctx.finalize_key.encrypt(&tag, &t_128);
            return tag;
        }
    };
}

/// Standard LeMac (single instance)
pub const LeMac = LeMacGeneric(1);

/// LeMAC-X2 (2 parallel instances using 256-bit SIMD)
pub const LeMacX2 = LeMacGeneric(2);

/// LeMAC-X4 (4 parallel instances using 512-bit SIMD)
pub const LeMacX4 = LeMacGeneric(4);

// Tests
test "LeMac basic" {
    const key: [16]u8 = @splat(0);
    const nonce: [16]u8 = @splat(0);
    const msg: [16]u8 = @splat(0);

    const ctx = LeMac.init(key);
    const tag = LeMac.mac(&ctx, &msg, nonce);

    // Test vector from reference Python implementation
    const expected = [_]u8{
        0x26, 0xfa, 0x47, 0x1b, 0x77, 0xfa, 0xcc, 0x73,
        0xec, 0x2f, 0x9b, 0x50, 0xbb, 0x1a, 0xf8, 0x64,
    };
    try std.testing.expectEqualSlices(u8, &expected, &tag);
}

test "LeMac empty message" {
    const key: [16]u8 = @splat(0);
    const nonce: [16]u8 = @splat(0);

    const ctx = LeMac.init(key);
    const tag = LeMac.mac(&ctx, &.{}, nonce);

    // Test vector from reference Python implementation
    const expected = [_]u8{
        0x52, 0x28, 0x2e, 0x85, 0x3c, 0x9c, 0xfe, 0xb5,
        0x53, 0x7d, 0x33, 0xfb, 0x91, 0x6a, 0x34, 0x1f,
    };
    try std.testing.expectEqualSlices(u8, &expected, &tag);
}

test "LeMac 65 byte message" {
    var key: [16]u8 = undefined;
    var nonce: [16]u8 = undefined;
    var msg: [65]u8 = undefined;

    for (0..16) |i| {
        key[i] = @intCast(i);
        nonce[i] = @intCast(i);
    }
    for (0..65) |i| {
        msg[i] = @intCast(i);
    }

    const ctx = LeMac.init(key);
    const tag = LeMac.mac(&ctx, &msg, nonce);

    // Test vector from reference Python implementation
    const expected = [_]u8{
        0xd5, 0x8d, 0xfd, 0xbe, 0x8b, 0x02, 0x24, 0xe1,
        0xd5, 0x10, 0x6a, 0xc4, 0xd7, 0x75, 0xbe, 0xef,
    };
    try std.testing.expectEqualSlices(u8, &expected, &tag);
}

test "LeMacX2 deterministic" {
    const key: [16]u8 = @splat(0);
    const nonce: [16]u8 = @splat(0);
    const msg: [16]u8 = @splat(0);

    const ctx = LeMacX2.init(key);
    const tag1 = LeMacX2.mac(&ctx, &msg, nonce);
    const tag2 = LeMacX2.mac(&ctx, &msg, nonce);

    // Same input should produce same output
    try std.testing.expectEqualSlices(u8, &tag1, &tag2);

    // X2 should produce a different tag than X1 (different domain separation)
    const ctx1 = LeMac.init(key);
    const tag_x1 = LeMac.mac(&ctx1, &msg, nonce);
    try std.testing.expect(!std.mem.eql(u8, &tag1, &tag_x1));
}

test "LeMacX4 deterministic" {
    const key: [16]u8 = @splat(0);
    const nonce: [16]u8 = @splat(0);
    const msg: [16]u8 = @splat(0);

    const ctx = LeMacX4.init(key);
    const tag1 = LeMacX4.mac(&ctx, &msg, nonce);
    const tag2 = LeMacX4.mac(&ctx, &msg, nonce);

    // Same input should produce same output
    try std.testing.expectEqualSlices(u8, &tag1, &tag2);

    // X4 should produce a different tag than X1 and X2
    const ctx1 = LeMac.init(key);
    const tag_x1 = LeMac.mac(&ctx1, &msg, nonce);
    try std.testing.expect(!std.mem.eql(u8, &tag1, &tag_x1));

    const ctx2 = LeMacX2.init(key);
    const tag_x2 = LeMacX2.mac(&ctx2, &msg, nonce);
    try std.testing.expect(!std.mem.eql(u8, &tag1, &tag_x2));
}
