//! Router-aware decoding for issue #15 Phase 2.
//!
//! `decode(data)` assumes today's Uniswap routers. Some routers reuse those
//! selectors with a different meaning, so calldata alone cannot tell them
//! apart:
//! - `exactInput((bytes,address,uint256,uint256,uint256))` (0xc04b8d59) is a
//!   fee path on Uniswap V3, a tick-spacing path on Slipstream, and a
//!   fee-less token path on Camelot V3 (Algebra).
//! - Universal Router command 0x10 is V4_SWAP on Uniswap's current router
//!   and an NFT command on pre-V4 and PancakeSwap routers.
//!
//! `decodeFor(router, data)` reads calldata with the right rules, and
//! `routerAt(chain_id, address)` maps a verified deployment to its `Router`.
//! SushiSwap V2/V3 and PancakeSwap V2/V3 routers share Uniswap's ABIs and map
//! to `.uniswap`, tagged with their `Protocol`.

const std = @import("std");
const reader = @import("abi_reader.zig");
const calldata = @import("calldata.zig");

const AddressPath = reader.AddressPath;
const AlgebraPath = reader.AlgebraPath;
const U256Array = reader.U256Array;
const Decoded = calldata.Decoded;

// ============================================================================
// Selectors
// ============================================================================

const keccak = @import("../keccak.zig");

pub const selectors = struct {
    // Aerodrome (Base) / Velodrome V2 (Optimism) Router, Route = (address from, address to, bool stable, address factory)
    pub const aerodrome_swap_exact_tokens_for_tokens = keccak.selector("swapExactTokensForTokens(uint256,uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_eth_for_tokens = keccak.selector("swapExactETHForTokens(uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_tokens_for_eth = keccak.selector("swapExactTokensForETH(uint256,uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_unsafe_swap_exact_tokens_for_tokens = keccak.selector("UNSAFE_swapExactTokensForTokens(uint256[],(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_tokens_for_tokens_fot = keccak.selector("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_eth_for_tokens_fot = keccak.selector("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,(address,address,bool,address)[],address,uint256)");
    pub const aerodrome_swap_exact_tokens_for_eth_fot = keccak.selector("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,(address,address,bool,address)[],address,uint256)");

    // Slipstream (Aerodrome/Velodrome CL) SwapRouter: int24 tickSpacing instead of uint24 fee
    pub const slipstream_exact_input_single = keccak.selector("exactInputSingle((address,address,int24,address,uint256,uint256,uint256,uint160))");
    pub const slipstream_exact_output_single = keccak.selector("exactOutputSingle((address,address,int24,address,uint256,uint256,uint256,uint160))");
    // exactInput / exactOutput share Uniswap SwapRouter's selectors (0xc04b8d59 / 0xf28c0498).

    // Camelot V2 (Arbitrum): fee-on-transfer only, `referrer` between `to` and `deadline`
    pub const camelot_v2_swap_exact_tokens_for_tokens_fot = keccak.selector("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,address,uint256)");
    pub const camelot_v2_swap_exact_eth_for_tokens_fot = keccak.selector("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,address,uint256)");
    pub const camelot_v2_swap_exact_tokens_for_eth_fot = keccak.selector("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,address,uint256)");

    // Camelot V3 (Algebra): no fee field, limitSqrtPrice
    pub const camelot_v3_exact_input_single = keccak.selector("exactInputSingle((address,address,address,uint256,uint256,uint256,uint160))");
    pub const camelot_v3_exact_input_single_fot = keccak.selector("exactInputSingleSupportingFeeOnTransferTokens((address,address,address,uint256,uint256,uint256,uint160))");
    // exactInput / exactOutput share Uniswap SwapRouter's selectors, with a fee-less path.

    // PancakeSwap SmartRouter StableSwapRouter
    pub const pancake_exact_input_stable_swap = keccak.selector("exactInputStableSwap(address[],uint256[],uint256,uint256,address)");
    pub const pancake_exact_output_stable_swap = keccak.selector("exactOutputStableSwap(address[],uint256[],uint256,uint256,address)");
};

// ============================================================================
// Routers and deployments
// ============================================================================

/// Decoding rules. Several protocols share one rule set.
pub const Router = enum {
    /// Uniswap V2Router02 / SwapRouter / SwapRouter02 / Universal Router with
    /// V4, and ABI-identical forks. Same as `decode`.
    uniswap,
    /// Pre-V4 Uniswap Universal Router: like `.uniswap`, but UR commands use
    /// `UrDialect.uniswap_v1`.
    uniswap_ur_v1,
    /// PancakeSwap SmartRouter: SwapRouter02 ABI plus stable swaps.
    pancake_smart_router,
    /// PancakeSwap Universal Router: `UrDialect.pancake`.
    pancake_ur,
    /// Aerodrome Router (Base) and Velodrome V2 Router (Optimism).
    aerodrome,
    /// Aerodrome/Velodrome Slipstream (CL) SwapRouter.
    slipstream,
    /// Camelot V2 Router (Arbitrum).
    camelot_v2,
    /// Camelot V3 (Algebra) SwapRouter (Arbitrum).
    camelot_v3,
};

pub const Protocol = enum { uniswap, sushiswap, pancakeswap, aerodrome, velodrome, camelot };

/// A verified router deployment.
pub const Deployment = struct {
    chain_id: u64,
    address: [20]u8,
    protocol: Protocol,
    router: Router,
};

/// Verified deployments (every address checked with `cast code` against the
/// chain's RPC). Unknown addresses are not guessed.
pub const deployments = [_]Deployment{};

/// The deployment at `address` on `chain_id`, or null if it is not a known
/// router.
pub fn routerAt(chain_id: u64, address: [20]u8) ?Deployment {
    _ = chain_id;
    _ = address;
    return null;
}

// ============================================================================
// Phase 2 decoded calls
// ============================================================================

/// Aerodrome/Velodrome `Route`.
pub const Route = struct {
    from: [20]u8,
    to: [20]u8,
    stable: bool,
    factory: [20]u8,
};

/// An ABI `Route[]` (static tuples, 4 words each), borrowed from calldata.
/// `decodeFor` checked every element and that `len() >= 1`.
pub const RouteArray = struct {
    words: []const u8,

    pub fn len(self: RouteArray) usize {
        _ = self;
        @panic("todo");
    }

    pub fn get(self: RouteArray, i: usize) Route {
        _ = self;
        _ = i;
        @panic("todo");
    }
};

pub const AerodromeExactIn = struct {
    amount_in: u256,
    amount_out_min: u256,
    routes: RouteArray,
    to: [20]u8,
    deadline: u256,
};

/// The input amount is the tx `value`.
pub const AerodromeEthExactIn = struct {
    amount_out_min: u256,
    routes: RouteArray,
    to: [20]u8,
    deadline: u256,
};

/// `UNSAFE_swapExactTokensForTokens`: the caller supplies every hop amount.
pub const AerodromeUnsafe = struct {
    amounts: U256Array,
    routes: RouteArray,
    to: [20]u8,
    deadline: u256,
};

pub const SlipstreamExactInputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    tick_spacing: i24,
    recipient: [20]u8,
    deadline: u256,
    amount_in: u256,
    amount_out_minimum: u256,
    sqrt_price_limit_x96: u160,
};

pub const SlipstreamExactOutputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    tick_spacing: i24,
    recipient: [20]u8,
    deadline: u256,
    amount_out: u256,
    amount_in_maximum: u256,
    sqrt_price_limit_x96: u160,
};

pub const CamelotV2ExactIn = struct {
    amount_in: u256,
    amount_out_min: u256,
    path: AddressPath,
    to: [20]u8,
    referrer: [20]u8,
    deadline: u256,
};

/// The input amount is the tx `value`.
pub const CamelotV2EthExactIn = struct {
    amount_out_min: u256,
    path: AddressPath,
    to: [20]u8,
    referrer: [20]u8,
    deadline: u256,
};

pub const AlgebraExactInputSingle = struct {
    token_in: [20]u8,
    token_out: [20]u8,
    recipient: [20]u8,
    deadline: u256,
    amount_in: u256,
    amount_out_minimum: u256,
    limit_sqrt_price: u160,
};

pub const AlgebraExactInput = struct {
    path: AlgebraPath,
    recipient: [20]u8,
    deadline: u256,
    amount_in: u256,
    amount_out_minimum: u256,
};

/// `path` is reversed (token out first).
pub const AlgebraExactOutput = struct {
    path: AlgebraPath,
    recipient: [20]u8,
    deadline: u256,
    amount_out: u256,
    amount_in_maximum: u256,
};

pub const PancakeStableExactIn = struct {
    path: AddressPath,
    /// `flags[i]` selects the stable pool for hop i.
    flags: U256Array,
    amount_in: u256,
    amount_out_min: u256,
    to: [20]u8,
};

pub const PancakeStableExactOut = struct {
    path: AddressPath,
    flags: U256Array,
    amount_out: u256,
    amount_in_max: u256,
    to: [20]u8,
};

// ============================================================================
// Decoding
// ============================================================================

/// Decode calldata sent to a `router`. Null for unknown selectors and any
/// malformed input; never panics and never allocates.
pub fn decodeFor(router: Router, data: []const u8) ?Decoded {
    _ = router;
    _ = data;
    return null;
}
