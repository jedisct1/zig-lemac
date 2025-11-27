//! LeMac - A fast AES-based MAC

pub const lemac = @import("lemac.zig");

pub const LeMac = lemac.LeMac;
pub const LeMacX2 = lemac.LeMacX2;
pub const LeMacX4 = lemac.LeMacX4;
pub const LeMacGeneric = lemac.LeMacGeneric;

test {
    _ = lemac;
}
