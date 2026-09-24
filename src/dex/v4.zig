//! Uniswap V4 swap plans, as carried by the Universal Router `V4_SWAP`
//! command (0x10).
//!
//! The command input is `abi.encode(bytes actions, bytes[] params)`: one
//! action byte per params entry (v4-periphery `BaseActionsRouter`). The
//! V4Router executes only the swap, settle and take actions typed below
//! (V4Router.sol:34-82); every other action byte arrives as `.other`.
//!
//! Swap params are located the way the contract locates them: the struct
//! starts at `params + word0` (CalldataDecoder.sol). Two struct layouts are
//! accepted:
//! - live (deployed routers): no `minHopPriceX36`. Single-hop `hookData`
//!   offset is 0x120; multi-hop `path` offset is 0x80.
//! - current v4-periphery main: with `minHopPriceX36`. Single-hop `hookData`
//!   offset is 0x140; multi-hop `path` offset is 0xa0.
//!
//! Same guarantees as `calldata.zig`: no allocation, no panics, and a
//! non-null `parsePlan` makes every accessor and iterator infallible.

const std = @import("std");
const reader = @import("abi_reader.zig");

const BytesArray = reader.BytesArray;
const U256Array = reader.U256Array;

/// v4-periphery Actions.sol values for the actions V4Router executes.
pub const actions = struct {
    pub const swap_exact_in_single: u8 = 0x06;
    pub const swap_exact_in: u8 = 0x07;
    pub const swap_exact_out_single: u8 = 0x08;
    pub const swap_exact_out: u8 = 0x09;
    pub const settle: u8 = 0x0b;
    pub const settle_all: u8 = 0x0c;
    pub const take: u8 = 0x0e;
    pub const take_all: u8 = 0x0f;
    pub const take_portion: u8 = 0x10;
};

/// A V4 pool identifier. `currency0 == 0` is native ETH.
pub const PoolKey = struct {
    currency0: [20]u8,
    currency1: [20]u8,
    fee: u24,
    tick_spacing: i24,
    hooks: [20]u8,
};

/// One hop of a multi-hop V4 path.
pub const PathKey = struct {
    intermediate_currency: [20]u8,
    fee: u24,
    tick_spacing: i24,
    hooks: [20]u8,
    hook_data: []const u8,
};

/// An ABI `PathKey[]`, borrowed from calldata; every element was validated.
pub const PathKeys = struct {
    /// The array's tail: element offset words start here.
    head: []const u8,
    count: usize,

    pub fn len(self: PathKeys) usize {
        _ = self;
        @panic("todo");
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: PathKeys, i: usize) PathKey {
        _ = self;
        _ = i;
        @panic("todo");
    }
};

pub const ExactInputSingle = struct {
    pool_key: PoolKey,
    zero_for_one: bool,
    amount_in: u128,
    amount_out_minimum: u128,
    /// Null in the live layout.
    min_hop_price_x36: ?u256,
    hook_data: []const u8,
};

pub const ExactOutputSingle = struct {
    pool_key: PoolKey,
    zero_for_one: bool,
    amount_out: u128,
    amount_in_maximum: u128,
    /// Null in the live layout.
    min_hop_price_x36: ?u256,
    hook_data: []const u8,
};

pub const ExactInput = struct {
    currency_in: [20]u8,
    path: PathKeys,
    /// Null in the live layout.
    min_hop_price_x36: ?U256Array,
    amount_in: u128,
    amount_out_minimum: u128,
};

/// `path` runs from the output currency backwards, as in V4Router.
pub const ExactOutput = struct {
    currency_out: [20]u8,
    path: PathKeys,
    /// Null in the live layout.
    min_hop_price_x36: ?U256Array,
    amount_out: u128,
    amount_in_maximum: u128,
};

pub const CurrencyAmount = struct {
    currency: [20]u8,
    amount: u256,
};

pub const CurrencyRecipientAmount = struct {
    currency: [20]u8,
    recipient: [20]u8,
    amount: u256,
};

pub const Action = struct {
    /// The raw action byte.
    raw: u8,
    payload: Payload,

    pub const Payload = union(enum) {
        swap_exact_in_single: ExactInputSingle,
        swap_exact_in: ExactInput,
        swap_exact_out_single: ExactOutputSingle,
        swap_exact_out: ExactOutput,
        settle: struct {
            currency: [20]u8,
            amount: u256,
            payer_is_user: bool,
        },
        /// `amount` is the maximum to settle.
        settle_all: CurrencyAmount,
        take: CurrencyRecipientAmount,
        /// `amount` is the minimum to take.
        take_all: CurrencyAmount,
        /// `amount` is the portion in basis points.
        take_portion: CurrencyRecipientAmount,
        /// Any other action byte, undecoded.
        other: struct {
            action: u8,
            params: []const u8,
        },
    };
};

/// A `V4_SWAP` plan: `actions.len == params.len()`.
pub const Plan = struct {
    actions: []const u8,
    params: BytesArray,

    pub fn iterator(self: Plan) Iterator {
        return .{ .actions = self.actions, .params = self.params };
    }

    pub const Iterator = struct {
        actions: []const u8,
        params: BytesArray,
        index: usize = 0,

        pub fn next(self: *Iterator) ?Action {
            _ = self;
            @panic("todo");
        }
    };
};

/// Parse and fully validate a `V4_SWAP` command input. Null for anything
/// malformed; never panics.
pub fn parsePlan(input: []const u8) ?Plan {
    _ = input;
    return null;
}
