//! Uniswap router calldata decoding (#15).
//!
//! `decode(tx.data)` recognizes swap calls to UniswapV2Router02, the V3
//! SwapRouter, SwapRouter02 and the Universal Router, and returns a typed view
//! over the calldata, or `null` for anything else.
//!
//! ```zig
//! const eth = @import("eth");
//!
//! const decoded = eth.dex.decode(tx.data) orelse continue;
//! switch (decoded) {
//!     .v2_swap_exact_tokens_for_tokens => |swap| {
//!         // swap.amount_in, swap.amount_out_min, swap.path, swap.to, swap.deadline
//!     },
//!     .v3_exact_input_single => |swap| {
//!         // swap.token_in, swap.token_out, swap.fee, swap.amount_in, ...
//!     },
//!     .universal_router_execute => |ur| {
//!         var it = ur.iterator();
//!         while (it.next()) |cmd| { ... }
//!     },
//!     else => {},
//! }
//! ```
//!
//! ## Guarantees
//! - No allocation. Paths, byte arrays and command inputs are views that
//!   borrow `data`, so they are valid only while `data` is.
//! - No panics on any input. Hostile mempool bytes return `null`.
//! - All validation happens in `decode`. A non-null result means every
//!   accessor and iterator below is infallible.
//! - Selectors are comptime keccak constants; dispatch is a `switch` on the
//!   first four bytes.
//!
//! ## Scope
//! `decode` looks at calldata only; checking `tx.to` against a router address
//! is the caller's job. Forks that reuse these ABIs (SushiSwap and PancakeSwap
//! V2 routers) decode the same way.

const std = @import("std");
const keccak = @import("../keccak.zig");

// ============================================================================
// Selectors
// ============================================================================

/// Comptime 4-byte selectors for every function `decode` recognizes.
pub const selectors = struct {
    // UniswapV2Router02
    pub const swap_exact_tokens_for_tokens = keccak.selector("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)");
    pub const swap_tokens_for_exact_tokens = keccak.selector("swapTokensForExactTokens(uint256,uint256,address[],address,uint256)");
    pub const swap_exact_eth_for_tokens = keccak.selector("swapExactETHForTokens(uint256,address[],address,uint256)");
    pub const swap_tokens_for_exact_eth = keccak.selector("swapTokensForExactETH(uint256,uint256,address[],address,uint256)");
    pub const swap_exact_tokens_for_eth = keccak.selector("swapExactTokensForETH(uint256,uint256,address[],address,uint256)");
    pub const swap_eth_for_exact_tokens = keccak.selector("swapETHForExactTokens(uint256,address[],address,uint256)");
    pub const swap_exact_tokens_for_tokens_fot = keccak.selector("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)");
    pub const swap_exact_eth_for_tokens_fot = keccak.selector("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)");
    pub const swap_exact_tokens_for_eth_fot = keccak.selector("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)");

    // V3 SwapRouter (params structs carry a deadline)
    pub const exact_input_single = keccak.selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))");
    pub const exact_input = keccak.selector("exactInput((bytes,address,uint256,uint256,uint256))");
    pub const exact_output_single = keccak.selector("exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))");
    pub const exact_output = keccak.selector("exactOutput((bytes,address,uint256,uint256,uint256))");

    // SwapRouter02 (V3 params structs without a deadline)
    pub const exact_input_single_02 = keccak.selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))");
    pub const exact_input_02 = keccak.selector("exactInput((bytes,address,uint256,uint256))");
    pub const exact_output_single_02 = keccak.selector("exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))");
    pub const exact_output_02 = keccak.selector("exactOutput((bytes,address,uint256,uint256))");

    // SwapRouter02 V2-style swaps (no deadline argument)
    pub const swap_exact_tokens_for_tokens_02 = keccak.selector("swapExactTokensForTokens(uint256,uint256,address[],address)");
    pub const swap_tokens_for_exact_tokens_02 = keccak.selector("swapTokensForExactTokens(uint256,uint256,address[],address)");

    // Multicall (SwapRouter and SwapRouter02)
    pub const multicall = keccak.selector("multicall(bytes[])");
    pub const multicall_deadline = keccak.selector("multicall(uint256,bytes[])");
    pub const multicall_blockhash = keccak.selector("multicall(bytes32,bytes[])");

    // Universal Router
    pub const execute = keccak.selector("execute(bytes,bytes[])");
    pub const execute_deadline = keccak.selector("execute(bytes,bytes[],uint256)");
};

// ============================================================================
// Views
// ============================================================================

/// An ABI `address[]`, borrowed from calldata. Every element's 12 padding
/// bytes were checked to be zero by `decode`.
pub const AddressPath = struct {
    /// `len() * 32` bytes: the array's elements, one ABI word each.
    words: []const u8,

    pub fn len(self: AddressPath) usize {
        _ = self;
        @panic("todo");
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: AddressPath, i: usize) [20]u8 {
        _ = self;
        _ = i;
        @panic("todo");
    }

    /// First element. Asserts `len() > 0`.
    pub fn first(self: AddressPath) [20]u8 {
        _ = self;
        @panic("todo");
    }

    /// Last element. Asserts `len() > 0`.
    pub fn last(self: AddressPath) [20]u8 {
        _ = self;
        @panic("todo");
    }
};

/// A Uniswap V3 packed path `token(20) fee(3) token(20) [fee(3) token(20)]...`,
/// borrowed from calldata. `decode` checked that its length is `20 + 23 * k`
/// with `k >= 1`.
///
/// Exact-output paths are encoded in reverse: `first()` is the token out and
/// `last()` is the token in.
pub const V3Path = struct {
    bytes: []const u8,

    pub const Hop = struct {
        token_a: [20]u8,
        fee: u24,
        token_b: [20]u8,
    };

    /// Number of pools traversed (`k`). Always at least 1.
    pub fn hops(self: V3Path) usize {
        _ = self;
        @panic("todo");
    }

    /// Hop `i`. Asserts `i < hops()`.
    pub fn hop(self: V3Path, i: usize) Hop {
        _ = self;
        _ = i;
        @panic("todo");
    }

    pub fn first(self: V3Path) [20]u8 {
        _ = self;
        @panic("todo");
    }

    pub fn last(self: V3Path) [20]u8 {
        _ = self;
        @panic("todo");
    }
};

/// An ABI `uint256[]`, borrowed from calldata.
pub const U256Array = struct {
    /// `len() * 32` bytes.
    words: []const u8,

    pub fn len(self: U256Array) usize {
        _ = self;
        @panic("todo");
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: U256Array, i: usize) u256 {
        _ = self;
        _ = i;
        @panic("todo");
    }
};

/// An ABI `bytes[]`, borrowed from calldata. `decode` checked every element's
/// offset and length.
pub const BytesArray = struct {
    /// The array's tail: starts at the first element's offset word, i.e.
    /// immediately after the length word. Element offsets are relative to it.
    head: []const u8,
    count: usize,

    pub fn len(self: BytesArray) usize {
        _ = self;
        @panic("todo");
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: BytesArray, i: usize) []const u8 {
        _ = self;
        _ = i;
        @panic("todo");
    }
};

// ============================================================================
// Decoded calls
// ============================================================================

/// Exact-input V2 swap. `deadline` is null for SwapRouter02's V2-style call.
pub const V2ExactIn = struct {
    amount_in: u256,
    amount_out_min: u256,
    path: AddressPath,
    to: [20]u8,
    deadline: ?u256,
};

/// Exact-output V2 swap. `deadline` is null for SwapRouter02's V2-style call.
pub const V2ExactOut = struct {
    amount_out: u256,
    amount_in_max: u256,
    path: AddressPath,
    to: [20]u8,
    deadline: ?u256,
};

/// Exact-input V2 swap paying ETH; the input amount is the tx `value`.
pub const V2EthExactIn = struct {
    amount_out_min: u256,
    path: AddressPath,
    to: [20]u8,
    deadline: u256,
};

/// Exact-output V2 swap paying ETH; the tx `value` is the maximum input.
pub const V2EthExactOut = struct {
    amount_out: u256,
    path: AddressPath,
    to: [20]u8,
    deadline: u256,
};

/// V3 `exactInputSingle`. `deadline` is null for SwapRouter02.
pub const V3ExactInputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    fee: u24,
    recipient: [20]u8,
    deadline: ?u256,
    amount_in: u256,
    amount_out_minimum: u256,
    sqrt_price_limit_x96: u160,
};

/// V3 `exactOutputSingle`. `deadline` is null for SwapRouter02.
pub const V3ExactOutputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    fee: u24,
    recipient: [20]u8,
    deadline: ?u256,
    amount_out: u256,
    amount_in_maximum: u256,
    sqrt_price_limit_x96: u160,
};

/// V3 `exactInput`. `deadline` is null for SwapRouter02.
pub const V3ExactInput = struct {
    path: V3Path,
    recipient: [20]u8,
    deadline: ?u256,
    amount_in: u256,
    amount_out_minimum: u256,
};

/// V3 `exactOutput`; `path` is reversed (token out first). `deadline` is null
/// for SwapRouter02.
pub const V3ExactOutput = struct {
    path: V3Path,
    recipient: [20]u8,
    deadline: ?u256,
    amount_out: u256,
    amount_in_maximum: u256,
};

pub const Decoded = union(enum) {
    // UniswapV2Router02
    v2_swap_exact_tokens_for_tokens: V2ExactIn,
    v2_swap_tokens_for_exact_tokens: V2ExactOut,
    v2_swap_exact_eth_for_tokens: V2EthExactIn,
    v2_swap_tokens_for_exact_eth: V2ExactOut,
    v2_swap_exact_tokens_for_eth: V2ExactIn,
    v2_swap_eth_for_exact_tokens: V2EthExactOut,
    v2_swap_exact_tokens_for_tokens_fot: V2ExactIn,
    v2_swap_exact_eth_for_tokens_fot: V2EthExactIn,
    v2_swap_exact_tokens_for_eth_fot: V2ExactIn,
    // SwapRouter02 V2-style (deadline null)
    v2_router02_swap_exact_tokens_for_tokens: V2ExactIn,
    v2_router02_swap_tokens_for_exact_tokens: V2ExactOut,
    // V3 SwapRouter and SwapRouter02
    v3_exact_input_single: V3ExactInputSingle,
    v3_exact_input: V3ExactInput,
    v3_exact_output_single: V3ExactOutputSingle,
    v3_exact_output: V3ExactOutput,
    // Batches
    multicall: Multicall,
    universal_router_execute: UniversalRouterExecute,
};

// ============================================================================
// Multicall
// ============================================================================

/// A SwapRouter/SwapRouter02 `multicall`. At most one of `deadline` and
/// `previous_blockhash` is set, matching the overload called.
pub const Multicall = struct {
    deadline: ?u256,
    previous_blockhash: ?[32]u8,
    calls: BytesArray,

    pub fn len(self: Multicall) usize {
        _ = self;
        @panic("todo");
    }

    pub fn iterator(self: Multicall) Iterator {
        return .{ .calls = self.calls };
    }

    /// One inner call. Inner swaps are decoded; everything else (including a
    /// nested multicall or Universal Router execute) is `.other`.
    pub const Call = union(enum) {
        swap: Decoded,
        other: struct {
            selector: [4]u8,
            data: []const u8,
        },
    };

    pub const Iterator = struct {
        calls: BytesArray,
        index: usize = 0,

        pub fn next(self: *Iterator) ?Call {
            _ = self;
            @panic("todo");
        }
    };
};

// ============================================================================
// Universal Router
// ============================================================================

/// Universal Router command types, from Commands.sol.
pub const command_types = struct {
    pub const flag_allow_revert: u8 = 0x80;
    pub const command_type_mask: u8 = 0x7f;

    pub const v3_swap_exact_in: u8 = 0x00;
    pub const v3_swap_exact_out: u8 = 0x01;
    pub const sweep: u8 = 0x04;
    pub const transfer: u8 = 0x05;
    pub const pay_portion: u8 = 0x06;
    pub const v2_swap_exact_in: u8 = 0x08;
    pub const v2_swap_exact_out: u8 = 0x09;
    pub const wrap_eth: u8 = 0x0b;
    pub const unwrap_weth: u8 = 0x0c;
};

/// Universal Router `execute`. `deadline` is null for `execute(bytes,bytes[])`.
pub const UniversalRouterExecute = struct {
    /// One byte per command.
    commands: []const u8,
    /// One ABI-encoded input per command; `inputs.len() == commands.len`.
    inputs: BytesArray,
    deadline: ?u256,

    pub fn iterator(self: UniversalRouterExecute) Iterator {
        return .{ .commands = self.commands, .inputs = self.inputs };
    }

    pub const Iterator = struct {
        commands: []const u8,
        inputs: BytesArray,
        index: usize = 0,

        pub fn next(self: *Iterator) ?Command {
            _ = self;
            @panic("todo");
        }
    };
};

/// One Universal Router command.
pub const Command = struct {
    /// The raw command byte.
    raw: u8,
    /// Bit 0x80: a revert in this command does not revert the transaction.
    allow_revert: bool,
    payload: Payload,

    /// V3 swap input. `min_hop_price_x36` is present only in the six-field
    /// layout of newer routers (path offset 0xc0); legacy five-field inputs
    /// (path offset 0xa0) leave it null.
    pub const V3SwapExactIn = struct {
        recipient: [20]u8,
        amount_in: u256,
        amount_out_min: u256,
        path: V3Path,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    /// Same layout as `V3SwapExactIn`; `path` is reversed (token out first).
    pub const V3SwapExactOut = struct {
        recipient: [20]u8,
        amount_out: u256,
        amount_in_max: u256,
        path: V3Path,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    pub const V2SwapExactIn = struct {
        recipient: [20]u8,
        amount_in: u256,
        amount_out_min: u256,
        path: AddressPath,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    pub const V2SwapExactOut = struct {
        recipient: [20]u8,
        amount_out: u256,
        amount_in_max: u256,
        path: AddressPath,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    pub const TokenRecipientAmount = struct {
        token: [20]u8,
        recipient: [20]u8,
        amount: u256,
    };

    pub const RecipientAmount = struct {
        recipient: [20]u8,
        amount: u256,
    };

    pub const Payload = union(enum) {
        v3_swap_exact_in: V3SwapExactIn,
        v3_swap_exact_out: V3SwapExactOut,
        v2_swap_exact_in: V2SwapExactIn,
        v2_swap_exact_out: V2SwapExactOut,
        /// `amount` is the minimum to sweep.
        sweep: TokenRecipientAmount,
        /// `amount` is the value transferred.
        transfer: TokenRecipientAmount,
        /// `amount` is the portion in basis points.
        pay_portion: TokenRecipientAmount,
        /// `amount` is the ETH amount to wrap.
        wrap_eth: RecipientAmount,
        /// `amount` is the minimum WETH to unwrap.
        unwrap_weth: RecipientAmount,
        /// Any other command type (V4_SWAP, PERMIT2_*, ...), undecoded.
        other: struct {
            command_type: u8,
            input: []const u8,
        },
    };
};

// ============================================================================
// Decoding
// ============================================================================

/// Decode router calldata. Returns null for unknown selectors and for any
/// malformed or truncated input; never panics and never allocates.
pub fn decode(data: []const u8) ?Decoded {
    _ = data;
    return null;
}
