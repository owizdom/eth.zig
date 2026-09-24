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
const uint256 = @import("../uint256.zig");

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
        return self.words.len / 32;
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: AddressPath, i: usize) [20]u8 {
        std.debug.assert(i < self.len());
        const word = self.words[i * 32 ..][0..32].*;
        return word[12..32].*;
    }

    /// First element. Asserts `len() > 0`.
    pub fn first(self: AddressPath) [20]u8 {
        std.debug.assert(self.len() > 0);
        return self.get(0);
    }

    /// Last element. Asserts `len() > 0`.
    pub fn last(self: AddressPath) [20]u8 {
        const n = self.len();
        std.debug.assert(n > 0);
        return self.get(n - 1);
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
        return (self.bytes.len - 20) / 23;
    }

    /// Hop `i`. Asserts `i < hops()`.
    pub fn hop(self: V3Path, i: usize) Hop {
        std.debug.assert(i < self.hops());
        const off = i * 23;
        return .{
            .token_a = self.bytes[off..][0..20].*,
            .fee = std.mem.readInt(u24, self.bytes[off + 20 ..][0..3], .big),
            .token_b = self.bytes[off + 23 ..][0..20].*,
        };
    }

    pub fn first(self: V3Path) [20]u8 {
        return self.bytes[0..20].*;
    }

    pub fn last(self: V3Path) [20]u8 {
        return self.bytes[self.bytes.len - 20 ..][0..20].*;
    }
};

/// An ABI `uint256[]`, borrowed from calldata.
pub const U256Array = struct {
    /// `len() * 32` bytes.
    words: []const u8,

    pub fn len(self: U256Array) usize {
        return self.words.len / 32;
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: U256Array, i: usize) u256 {
        std.debug.assert(i < self.len());
        return uint256.fromBigEndianBytes(self.words[i * 32 ..][0..32].*);
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
        return self.count;
    }

    /// Element `i`. Asserts `i < len()`.
    pub fn get(self: BytesArray, i: usize) []const u8 {
        std.debug.assert(i < self.count);
        return bytesAt(self.head, 0, i * 32) orelse unreachable;
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
        return self.calls.len();
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
            if (self.index >= self.calls.len()) return null;
            const inner = self.calls.get(self.index);
            self.index += 1;
            const sel = readSelectorU32(inner);
            if (isSwapSelector(sel)) {
                const decoded = decodeDispatch(inner, false) orelse unreachable;
                return .{ .swap = decoded };
            }
            return .{ .other = .{ .selector = inner[0..4].*, .data = inner } };
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
            if (self.index >= self.commands.len) return null;
            const raw = self.commands[self.index];
            const input = self.inputs.get(self.index);
            self.index += 1;
            const command_type = raw & command_types.command_type_mask;
            const payload = parseCommandPayload(command_type, input) orelse unreachable;
            return .{
                .raw = raw,
                .allow_revert = (raw & command_types.flag_allow_revert) != 0,
                .payload = payload,
            };
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
// Decoding: safe arithmetic and word-level readers
// ============================================================================
//
// Every helper below either returns null or a value; none can panic. Offsets
// and lengths taken from calldata are always u256 words, range-checked into
// usize before any arithmetic touches them, and every byte range is bounds
// checked against `data.len` before it is sliced.

fn addChecked(a: usize, b: usize) ?usize {
    return std.math.add(usize, a, b) catch null;
}

fn mulChecked(a: usize, b: usize) ?usize {
    return std.math.mul(usize, a, b) catch null;
}

fn wordToUsize(w: u256) ?usize {
    if (w > std.math.maxInt(usize)) return null;
    return @intCast(w);
}

fn isZeroSlice(s: []const u8) bool {
    for (s) |b| {
        if (b != 0) return false;
    }
    return true;
}

/// Read the 32-byte word at `offset`, or null if it runs past `data`.
fn readWord(data: []const u8, offset: usize) ?[32]u8 {
    const end = addChecked(offset, 32) orelse return null;
    if (end > data.len) return null;
    return data[offset..][0..32].*;
}

fn readU256At(data: []const u8, offset: usize) ?u256 {
    const w = readWord(data, offset) orelse return null;
    return uint256.fromBigEndianBytes(w);
}

/// Read a word meant to be used as an offset or length, range-checked into
/// `usize` before any arithmetic can touch it.
fn readOffset(data: []const u8, word_pos: usize) ?usize {
    const w = readU256At(data, word_pos) orelse return null;
    return wordToUsize(w);
}

/// A clean ABI address word: 12 zero high bytes, address in the low 20.
fn readAddressAt(data: []const u8, pos: usize) ?[20]u8 {
    const w = readWord(data, pos) orelse return null;
    if (!isZeroSlice(w[0..12])) return null;
    return w[12..32].*;
}

/// A clean ABI bool word: all zero except the last byte, which is 0 or 1.
fn readBoolAt(data: []const u8, pos: usize) ?bool {
    const w = readWord(data, pos) orelse return null;
    if (!isZeroSlice(w[0..31])) return null;
    if (w[31] > 1) return null;
    return w[31] == 1;
}

/// A clean ABI uint24 word: only the low 3 bytes may be set.
fn readFeeAt(data: []const u8, pos: usize) ?u24 {
    const w = readWord(data, pos) orelse return null;
    if (!isZeroSlice(w[0..29])) return null;
    return std.mem.readInt(u24, w[29..32], .big);
}

/// A clean ABI uint160 word: only the low 20 bytes may be set.
fn readU160At(data: []const u8, pos: usize) ?u160 {
    const w = readWord(data, pos) orelse return null;
    if (!isZeroSlice(w[0..12])) return null;
    return std.mem.readInt(u160, w[12..32], .big);
}

fn readSelectorU32(data: []const u8) u32 {
    return std.mem.readInt(u32, data[0..4], .big);
}

fn selU32(s: [4]u8) u32 {
    return std.mem.readInt(u32, &s, .big);
}

// ============================================================================
// Decoding: dynamic value locators
// ============================================================================
//
// `base` is the start of the enclosing tuple or argument block; `offset_word_pos`
// is the absolute position of the word holding the offset, relative to `base`.

/// Locate a dynamic `bytes` value's content.
fn bytesAt(data: []const u8, base: usize, offset_word_pos: usize) ?[]const u8 {
    const off = readOffset(data, offset_word_pos) orelse return null;
    const start = addChecked(base, off) orelse return null;
    const len = wordToUsize(readU256At(data, start) orelse return null) orelse return null;
    const content_start = addChecked(start, 32) orelse return null;
    const content_end = addChecked(content_start, len) orelse return null;
    if (content_end > data.len) return null;
    return data[content_start..content_end];
}

const ArrayHead = struct {
    /// First element's byte position (right after the length word).
    start: usize,
    /// End of the head words region (`start + count * 32`).
    end: usize,
    count: usize,
};

/// Locate a dynamic array's length and head-words region, bounds checked.
fn arrayHeadAt(data: []const u8, base: usize, offset_word_pos: usize) ?ArrayHead {
    const off = readOffset(data, offset_word_pos) orelse return null;
    const arr_start = addChecked(base, off) orelse return null;
    const count = wordToUsize(readU256At(data, arr_start) orelse return null) orelse return null;
    const head_start = addChecked(arr_start, 32) orelse return null;
    const head_len = mulChecked(count, 32) orelse return null;
    const head_end = addChecked(head_start, head_len) orelse return null;
    if (head_end > data.len) return null;
    return .{ .start = head_start, .end = head_end, .count = count };
}

/// An `address[]`, validating every element's padding eagerly.
fn addressArrayAt(data: []const u8, base: usize, offset_word_pos: usize) ?AddressPath {
    const h = arrayHeadAt(data, base, offset_word_pos) orelse return null;
    const words = data[h.start..h.end];
    var i: usize = 0;
    while (i < h.count) : (i += 1) {
        if (!isZeroSlice(words[i * 32 ..][0..12])) return null;
    }
    return .{ .words = words };
}

/// A `uint256[]`; every 32-byte word is a valid element.
fn u256ArrayAt(data: []const u8, base: usize, offset_word_pos: usize) ?U256Array {
    const h = arrayHeadAt(data, base, offset_word_pos) orelse return null;
    return .{ .words = data[h.start..h.end] };
}

/// A `bytes[]` array's location (element validation happens at each call
/// site, since what counts as "valid" differs between multicall and UR).
fn bytesArrayAt(data: []const u8, base: usize, offset_word_pos: usize) ?BytesArray {
    const h = arrayHeadAt(data, base, offset_word_pos) orelse return null;
    return .{ .head = data[h.start..], .count = h.count };
}

/// `k` for a V3 packed path of this byte length, or null if it isn't
/// `20 + 23 * k` with `k >= 1`.
fn v3PathHops(len: usize) ?usize {
    if (len < 43) return null;
    const rem = len - 20;
    if (rem % 23 != 0) return null;
    return rem / 23;
}

// ============================================================================
// Decoding: UniswapV2Router02 / SwapRouter02 V2-style swaps
// ============================================================================
//
// Static head: amount0, amount1, path offset, to, [deadline]. `has_deadline`
// is false only for the SwapRouter02 V2-style overloads (no trailing word).

fn parseV2ExactIn(data: []const u8, args_base: usize, has_deadline: bool) ?V2ExactIn {
    const amount_in = readU256At(data, args_base) orelse return null;
    const amount_out_min = readU256At(data, args_base + 32) orelse return null;
    const path = addressArrayAt(data, args_base, args_base + 64) orelse return null;
    const to = readAddressAt(data, args_base + 96) orelse return null;
    const deadline: ?u256 = if (has_deadline) (readU256At(data, args_base + 128) orelse return null) else null;
    return .{ .amount_in = amount_in, .amount_out_min = amount_out_min, .path = path, .to = to, .deadline = deadline };
}

fn parseV2ExactOut(data: []const u8, args_base: usize, has_deadline: bool) ?V2ExactOut {
    const amount_out = readU256At(data, args_base) orelse return null;
    const amount_in_max = readU256At(data, args_base + 32) orelse return null;
    const path = addressArrayAt(data, args_base, args_base + 64) orelse return null;
    const to = readAddressAt(data, args_base + 96) orelse return null;
    const deadline: ?u256 = if (has_deadline) (readU256At(data, args_base + 128) orelse return null) else null;
    return .{ .amount_out = amount_out, .amount_in_max = amount_in_max, .path = path, .to = to, .deadline = deadline };
}

fn parseV2EthExactIn(data: []const u8, args_base: usize) ?V2EthExactIn {
    const amount_out_min = readU256At(data, args_base) orelse return null;
    const path = addressArrayAt(data, args_base, args_base + 32) orelse return null;
    const to = readAddressAt(data, args_base + 64) orelse return null;
    const deadline = readU256At(data, args_base + 96) orelse return null;
    return .{ .amount_out_min = amount_out_min, .path = path, .to = to, .deadline = deadline };
}

fn parseV2EthExactOut(data: []const u8, args_base: usize) ?V2EthExactOut {
    const amount_out = readU256At(data, args_base) orelse return null;
    const path = addressArrayAt(data, args_base, args_base + 32) orelse return null;
    const to = readAddressAt(data, args_base + 64) orelse return null;
    const deadline = readU256At(data, args_base + 96) orelse return null;
    return .{ .amount_out = amount_out, .path = path, .to = to, .deadline = deadline };
}

// ============================================================================
// Decoding: V3 SwapRouter / SwapRouter02
// ============================================================================
//
// The *Single params are a static tuple, inline right after the selector.
// The path-based params contain a dynamic `bytes path`, so the tuple itself
// is dynamic and reached through one outer offset word.

fn parseV3ExactInputSingle(data: []const u8, has_deadline: bool) ?V3ExactInputSingle {
    const t: usize = 4;
    const token_in = readAddressAt(data, t) orelse return null;
    const token_out = readAddressAt(data, t + 32) orelse return null;
    const fee = readFeeAt(data, t + 64) orelse return null;
    const recipient = readAddressAt(data, t + 96) orelse return null;
    var pos = t + 128;
    const deadline: ?u256 = if (has_deadline) blk: {
        const d = readU256At(data, pos) orelse return null;
        pos += 32;
        break :blk d;
    } else null;
    const amount_in = readU256At(data, pos) orelse return null;
    const amount_out_minimum = readU256At(data, pos + 32) orelse return null;
    const sqrt_price_limit_x96 = readU160At(data, pos + 64) orelse return null;
    return .{
        .token_in = token_in,
        .token_out = token_out,
        .fee = fee,
        .recipient = recipient,
        .deadline = deadline,
        .amount_in = amount_in,
        .amount_out_minimum = amount_out_minimum,
        .sqrt_price_limit_x96 = sqrt_price_limit_x96,
    };
}

fn parseV3ExactOutputSingle(data: []const u8, has_deadline: bool) ?V3ExactOutputSingle {
    const t: usize = 4;
    const token_in = readAddressAt(data, t) orelse return null;
    const token_out = readAddressAt(data, t + 32) orelse return null;
    const fee = readFeeAt(data, t + 64) orelse return null;
    const recipient = readAddressAt(data, t + 96) orelse return null;
    var pos = t + 128;
    const deadline: ?u256 = if (has_deadline) blk: {
        const d = readU256At(data, pos) orelse return null;
        pos += 32;
        break :blk d;
    } else null;
    const amount_out = readU256At(data, pos) orelse return null;
    const amount_in_maximum = readU256At(data, pos + 32) orelse return null;
    const sqrt_price_limit_x96 = readU160At(data, pos + 64) orelse return null;
    return .{
        .token_in = token_in,
        .token_out = token_out,
        .fee = fee,
        .recipient = recipient,
        .deadline = deadline,
        .amount_out = amount_out,
        .amount_in_maximum = amount_in_maximum,
        .sqrt_price_limit_x96 = sqrt_price_limit_x96,
    };
}

fn parseV3ExactInput(data: []const u8, has_deadline: bool) ?V3ExactInput {
    const args_base: usize = 4;
    const off = readOffset(data, args_base) orelse return null;
    const t = addChecked(args_base, off) orelse return null;
    const path_bytes = bytesAt(data, t, t) orelse return null;
    if (v3PathHops(path_bytes.len) == null) return null;
    const recipient = readAddressAt(data, t + 32) orelse return null;
    var pos = t + 64;
    const deadline: ?u256 = if (has_deadline) blk: {
        const d = readU256At(data, pos) orelse return null;
        pos += 32;
        break :blk d;
    } else null;
    const amount_in = readU256At(data, pos) orelse return null;
    const amount_out_minimum = readU256At(data, pos + 32) orelse return null;
    return .{ .path = .{ .bytes = path_bytes }, .recipient = recipient, .deadline = deadline, .amount_in = amount_in, .amount_out_minimum = amount_out_minimum };
}

fn parseV3ExactOutput(data: []const u8, has_deadline: bool) ?V3ExactOutput {
    const args_base: usize = 4;
    const off = readOffset(data, args_base) orelse return null;
    const t = addChecked(args_base, off) orelse return null;
    const path_bytes = bytesAt(data, t, t) orelse return null;
    if (v3PathHops(path_bytes.len) == null) return null;
    const recipient = readAddressAt(data, t + 32) orelse return null;
    var pos = t + 64;
    const deadline: ?u256 = if (has_deadline) blk: {
        const d = readU256At(data, pos) orelse return null;
        pos += 32;
        break :blk d;
    } else null;
    const amount_out = readU256At(data, pos) orelse return null;
    const amount_in_maximum = readU256At(data, pos + 32) orelse return null;
    return .{ .path = .{ .bytes = path_bytes }, .recipient = recipient, .deadline = deadline, .amount_out = amount_out, .amount_in_maximum = amount_in_maximum };
}

// ============================================================================
// Decoding: Universal Router command payloads
// ============================================================================
//
// Each `input` is itself an ABI argument block (no selector). Slots 0-4 are
// recipient/amount/amount/pathOffset/bool; slot 5 (present when the path
// offset is >= 0xc0) is an offset to `minHopPriceX36`, per BytesLib's
// `toLengthOffset` convention (spec section 5).

fn parseV3SwapExactIn(input: []const u8) ?Command.V3SwapExactIn {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount_in = readU256At(input, 32) orelse return null;
    const amount_out_min = readU256At(input, 64) orelse return null;
    const path_offset_word = readU256At(input, 96) orelse return null;
    const path_bytes = bytesAt(input, 0, 96) orelse return null;
    if (v3PathHops(path_bytes.len) == null) return null;
    const payer_is_user = readBoolAt(input, 128) orelse return null;
    const min_hop: ?U256Array = if (path_offset_word >= 0xc0) (u256ArrayAt(input, 0, 160) orelse return null) else null;
    return .{
        .recipient = recipient,
        .amount_in = amount_in,
        .amount_out_min = amount_out_min,
        .path = .{ .bytes = path_bytes },
        .payer_is_user = payer_is_user,
        .min_hop_price_x36 = min_hop,
    };
}

fn parseV3SwapExactOut(input: []const u8) ?Command.V3SwapExactOut {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount_out = readU256At(input, 32) orelse return null;
    const amount_in_max = readU256At(input, 64) orelse return null;
    const path_offset_word = readU256At(input, 96) orelse return null;
    const path_bytes = bytesAt(input, 0, 96) orelse return null;
    if (v3PathHops(path_bytes.len) == null) return null;
    const payer_is_user = readBoolAt(input, 128) orelse return null;
    const min_hop: ?U256Array = if (path_offset_word >= 0xc0) (u256ArrayAt(input, 0, 160) orelse return null) else null;
    return .{
        .recipient = recipient,
        .amount_out = amount_out,
        .amount_in_max = amount_in_max,
        .path = .{ .bytes = path_bytes },
        .payer_is_user = payer_is_user,
        .min_hop_price_x36 = min_hop,
    };
}

fn parseV2SwapExactIn(input: []const u8) ?Command.V2SwapExactIn {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount_in = readU256At(input, 32) orelse return null;
    const amount_out_min = readU256At(input, 64) orelse return null;
    const path_offset_word = readU256At(input, 96) orelse return null;
    const path = addressArrayAt(input, 0, 96) orelse return null;
    const payer_is_user = readBoolAt(input, 128) orelse return null;
    const min_hop: ?U256Array = if (path_offset_word >= 0xc0) (u256ArrayAt(input, 0, 160) orelse return null) else null;
    return .{
        .recipient = recipient,
        .amount_in = amount_in,
        .amount_out_min = amount_out_min,
        .path = path,
        .payer_is_user = payer_is_user,
        .min_hop_price_x36 = min_hop,
    };
}

fn parseV2SwapExactOut(input: []const u8) ?Command.V2SwapExactOut {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount_out = readU256At(input, 32) orelse return null;
    const amount_in_max = readU256At(input, 64) orelse return null;
    const path_offset_word = readU256At(input, 96) orelse return null;
    const path = addressArrayAt(input, 0, 96) orelse return null;
    const payer_is_user = readBoolAt(input, 128) orelse return null;
    const min_hop: ?U256Array = if (path_offset_word >= 0xc0) (u256ArrayAt(input, 0, 160) orelse return null) else null;
    return .{
        .recipient = recipient,
        .amount_out = amount_out,
        .amount_in_max = amount_in_max,
        .path = path,
        .payer_is_user = payer_is_user,
        .min_hop_price_x36 = min_hop,
    };
}

fn parseTokenRecipientAmount(input: []const u8) ?Command.TokenRecipientAmount {
    const token = readAddressAt(input, 0) orelse return null;
    const recipient = readAddressAt(input, 32) orelse return null;
    const amount = readU256At(input, 64) orelse return null;
    return .{ .token = token, .recipient = recipient, .amount = amount };
}

fn parseRecipientAmount(input: []const u8) ?Command.RecipientAmount {
    const recipient = readAddressAt(input, 0) orelse return null;
    const amount = readU256At(input, 32) orelse return null;
    return .{ .recipient = recipient, .amount = amount };
}

/// Dispatch on the masked command type. Unknown types always succeed as
/// `.other`; known types must parse or the whole command is invalid.
fn parseCommandPayload(command_type: u8, input: []const u8) ?Command.Payload {
    return switch (command_type) {
        command_types.v3_swap_exact_in => .{ .v3_swap_exact_in = parseV3SwapExactIn(input) orelse return null },
        command_types.v3_swap_exact_out => .{ .v3_swap_exact_out = parseV3SwapExactOut(input) orelse return null },
        command_types.v2_swap_exact_in => .{ .v2_swap_exact_in = parseV2SwapExactIn(input) orelse return null },
        command_types.v2_swap_exact_out => .{ .v2_swap_exact_out = parseV2SwapExactOut(input) orelse return null },
        command_types.sweep => .{ .sweep = parseTokenRecipientAmount(input) orelse return null },
        command_types.transfer => .{ .transfer = parseTokenRecipientAmount(input) orelse return null },
        command_types.pay_portion => .{ .pay_portion = parseTokenRecipientAmount(input) orelse return null },
        command_types.wrap_eth => .{ .wrap_eth = parseRecipientAmount(input) orelse return null },
        command_types.unwrap_weth => .{ .unwrap_weth = parseRecipientAmount(input) orelse return null },
        else => .{ .other = .{ .command_type = command_type, .input = input } },
    };
}

/// `execute(bytes commands, bytes[] inputs, [uint256 deadline])`. Every
/// command's payload is validated here so the iterator can be infallible.
fn parseUniversalRouterExecute(data: []const u8, args_base: usize, has_deadline: bool) ?UniversalRouterExecute {
    const commands = bytesAt(data, args_base, args_base) orelse return null;
    const inputs = bytesArrayAt(data, args_base, args_base + 32) orelse return null;
    if (commands.len != inputs.count) return null;
    const deadline: ?u256 = if (has_deadline) (readU256At(data, args_base + 64) orelse return null) else null;

    var i: usize = 0;
    while (i < commands.len) : (i += 1) {
        const input_i = bytesAt(inputs.head, 0, i * 32) orelse return null;
        const command_type = commands[i] & command_types.command_type_mask;
        _ = parseCommandPayload(command_type, input_i) orelse return null;
    }
    return .{ .commands = commands, .inputs = inputs, .deadline = deadline };
}

// ============================================================================
// Decoding: Multicall
// ============================================================================

const MulticallKind = enum { plain, with_deadline, with_blockhash };

/// Every inner call is validated eagerly: too short is fatal, a recognized
/// swap selector must fully decode, and anything else (including a nested
/// multicall or UR execute) is accepted as `.other` without recursing.
fn parseMulticall(data: []const u8, args_base: usize, kind: MulticallKind) ?Multicall {
    var deadline: ?u256 = null;
    var previous_blockhash: ?[32]u8 = null;
    var calls_offset_pos = args_base;
    switch (kind) {
        .plain => {},
        .with_deadline => {
            deadline = readU256At(data, args_base) orelse return null;
            calls_offset_pos = args_base + 32;
        },
        .with_blockhash => {
            previous_blockhash = readWord(data, args_base) orelse return null;
            calls_offset_pos = args_base + 32;
        },
    }
    const calls = bytesArrayAt(data, args_base, calls_offset_pos) orelse return null;

    var i: usize = 0;
    while (i < calls.count) : (i += 1) {
        const inner = bytesAt(calls.head, 0, i * 32) orelse return null;
        if (inner.len < 4) return null;
        const sel = readSelectorU32(inner);
        if (isSwapSelector(sel)) {
            _ = decodeDispatch(inner, false) orelse return null;
        }
    }
    return .{ .deadline = deadline, .previous_blockhash = previous_blockhash, .calls = calls };
}

// ============================================================================
// Decoding: top-level dispatch
// ============================================================================

fn isBatchSelector(sel: u32) bool {
    return sel == selU32(selectors.multicall) or
        sel == selU32(selectors.multicall_deadline) or
        sel == selU32(selectors.multicall_blockhash) or
        sel == selU32(selectors.execute) or
        sel == selU32(selectors.execute_deadline);
}

/// True for every selector `decodeDispatch` can turn into a swap `Decoded`
/// (i.e. every case below except the two batch dispatchers). Used to decide
/// whether a multicall inner call is a swap that must fully decode, or an
/// opaque `.other` payload.
fn isSwapSelector(sel: u32) bool {
    return switch (sel) {
        selU32(selectors.swap_exact_tokens_for_tokens),
        selU32(selectors.swap_tokens_for_exact_tokens),
        selU32(selectors.swap_exact_eth_for_tokens),
        selU32(selectors.swap_tokens_for_exact_eth),
        selU32(selectors.swap_exact_tokens_for_eth),
        selU32(selectors.swap_eth_for_exact_tokens),
        selU32(selectors.swap_exact_tokens_for_tokens_fot),
        selU32(selectors.swap_exact_eth_for_tokens_fot),
        selU32(selectors.swap_exact_tokens_for_eth_fot),
        selU32(selectors.exact_input_single),
        selU32(selectors.exact_input),
        selU32(selectors.exact_output_single),
        selU32(selectors.exact_output),
        selU32(selectors.exact_input_single_02),
        selU32(selectors.exact_input_02),
        selU32(selectors.exact_output_single_02),
        selU32(selectors.exact_output_02),
        selU32(selectors.swap_exact_tokens_for_tokens_02),
        selU32(selectors.swap_tokens_for_exact_tokens_02),
        => true,
        else => false,
    };
}

/// Shared dispatch for `decode` and for multicall/UR-execute inner calls.
/// `allow_batch = false` refuses the two batch selectors, which bounds
/// recursion to depth 1 (a nested multicall or UR execute is never entered;
/// callers treat that refusal as `.other`).
fn decodeDispatch(data: []const u8, allow_batch: bool) ?Decoded {
    if (data.len < 4) return null;
    const sel = readSelectorU32(data);
    if (!allow_batch and isBatchSelector(sel)) return null;
    const args_base: usize = 4;

    return switch (sel) {
        selU32(selectors.swap_exact_tokens_for_tokens) => Decoded{ .v2_swap_exact_tokens_for_tokens = parseV2ExactIn(data, args_base, true) orelse return null },
        selU32(selectors.swap_tokens_for_exact_tokens) => Decoded{ .v2_swap_tokens_for_exact_tokens = parseV2ExactOut(data, args_base, true) orelse return null },
        selU32(selectors.swap_exact_eth_for_tokens) => Decoded{ .v2_swap_exact_eth_for_tokens = parseV2EthExactIn(data, args_base) orelse return null },
        selU32(selectors.swap_tokens_for_exact_eth) => Decoded{ .v2_swap_tokens_for_exact_eth = parseV2ExactOut(data, args_base, true) orelse return null },
        selU32(selectors.swap_exact_tokens_for_eth) => Decoded{ .v2_swap_exact_tokens_for_eth = parseV2ExactIn(data, args_base, true) orelse return null },
        selU32(selectors.swap_eth_for_exact_tokens) => Decoded{ .v2_swap_eth_for_exact_tokens = parseV2EthExactOut(data, args_base) orelse return null },
        selU32(selectors.swap_exact_tokens_for_tokens_fot) => Decoded{ .v2_swap_exact_tokens_for_tokens_fot = parseV2ExactIn(data, args_base, true) orelse return null },
        selU32(selectors.swap_exact_eth_for_tokens_fot) => Decoded{ .v2_swap_exact_eth_for_tokens_fot = parseV2EthExactIn(data, args_base) orelse return null },
        selU32(selectors.swap_exact_tokens_for_eth_fot) => Decoded{ .v2_swap_exact_tokens_for_eth_fot = parseV2ExactIn(data, args_base, true) orelse return null },
        selU32(selectors.swap_exact_tokens_for_tokens_02) => Decoded{ .v2_router02_swap_exact_tokens_for_tokens = parseV2ExactIn(data, args_base, false) orelse return null },
        selU32(selectors.swap_tokens_for_exact_tokens_02) => Decoded{ .v2_router02_swap_tokens_for_exact_tokens = parseV2ExactOut(data, args_base, false) orelse return null },
        selU32(selectors.exact_input_single) => Decoded{ .v3_exact_input_single = parseV3ExactInputSingle(data, true) orelse return null },
        selU32(selectors.exact_input_single_02) => Decoded{ .v3_exact_input_single = parseV3ExactInputSingle(data, false) orelse return null },
        selU32(selectors.exact_output_single) => Decoded{ .v3_exact_output_single = parseV3ExactOutputSingle(data, true) orelse return null },
        selU32(selectors.exact_output_single_02) => Decoded{ .v3_exact_output_single = parseV3ExactOutputSingle(data, false) orelse return null },
        selU32(selectors.exact_input) => Decoded{ .v3_exact_input = parseV3ExactInput(data, true) orelse return null },
        selU32(selectors.exact_input_02) => Decoded{ .v3_exact_input = parseV3ExactInput(data, false) orelse return null },
        selU32(selectors.exact_output) => Decoded{ .v3_exact_output = parseV3ExactOutput(data, true) orelse return null },
        selU32(selectors.exact_output_02) => Decoded{ .v3_exact_output = parseV3ExactOutput(data, false) orelse return null },
        selU32(selectors.multicall) => Decoded{ .multicall = parseMulticall(data, args_base, .plain) orelse return null },
        selU32(selectors.multicall_deadline) => Decoded{ .multicall = parseMulticall(data, args_base, .with_deadline) orelse return null },
        selU32(selectors.multicall_blockhash) => Decoded{ .multicall = parseMulticall(data, args_base, .with_blockhash) orelse return null },
        selU32(selectors.execute) => Decoded{ .universal_router_execute = parseUniversalRouterExecute(data, args_base, false) orelse return null },
        selU32(selectors.execute_deadline) => Decoded{ .universal_router_execute = parseUniversalRouterExecute(data, args_base, true) orelse return null },
        else => null,
    };
}

/// Decode router calldata. Returns null for unknown selectors and for any
/// malformed or truncated input; never panics and never allocates.
pub fn decode(data: []const u8) ?Decoded {
    return decodeDispatch(data, true);
}
