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
//! - Decoding is linear in `data.len`; non-canonical, aliased `bytes[]`
//!   encodings (multicall calls, UR inputs) are rejected.
//!
//! ## Scope
//! `decode` looks at calldata only; checking `tx.to` against a router address
//! is the caller's job. Forks that reuse these ABIs (SushiSwap and PancakeSwap
//! V2 routers) decode the same way.
//!
//! ## Known limits
//! Validation is strict ABI (abicoder v2), so a few inputs that the
//! Universal Router or V2Router02 execute are rejected: dirty address or
//! bool padding bits, V3 paths with trailing bytes, and short static command
//! inputs. One rejected command makes the whole `execute` or `multicall`
//! null. `PAY_PORTION_FULL_PRECISION` (`0x07`) and other untyped Universal
//! Router commands arrive as `.other`.

const std = @import("std");
const keccak = @import("../keccak.zig");
const uint256 = @import("../uint256.zig");
const reader = @import("abi_reader.zig");
const routers = @import("routers.zig");
/// Uniswap V4 swap plans (Universal Router `V4_SWAP`).
pub const v4 = @import("v4.zig");
pub const AddressPath = reader.AddressPath;
pub const AlgebraPath = reader.AlgebraPath;
pub const V3Path = reader.V3Path;
pub const U256Array = reader.U256Array;
pub const BytesArray = reader.BytesArray;
const addChecked = reader.addChecked;
const mulChecked = reader.mulChecked;
const roundUpWord = reader.roundUpWord;
const wordToUsize = reader.wordToUsize;
const isZeroSlice = reader.isZeroSlice;
const readWord = reader.readWord;
const readU256At = reader.readU256At;
const readOffset = reader.readOffset;
const readAddressAt = reader.readAddressAt;
const readBoolAt = reader.readBoolAt;
const readFeeAt = reader.readFeeAt;
const readU160At = reader.readU160At;
const readSelectorU32 = reader.readSelectorU32;
const selU32 = reader.selU32;
const bytesAt = reader.bytesAt;
const arrayHeadAt = reader.arrayHeadAt;
const addressArrayAt = reader.addressArrayAt;
const u256ArrayAt = reader.u256ArrayAt;
const bytesArrayAt = reader.bytesArrayAt;
const v3PathHops = reader.v3PathHops;
const ArrayHead = reader.ArrayHead;

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
    swap_router02_swap_exact_tokens_for_tokens: V2ExactIn,
    swap_router02_swap_tokens_for_exact_tokens: V2ExactOut,
    // V3 SwapRouter and SwapRouter02
    v3_exact_input_single: V3ExactInputSingle,
    v3_exact_input: V3ExactInput,
    v3_exact_output_single: V3ExactOutputSingle,
    v3_exact_output: V3ExactOutput,
    // Batches
    multicall: Multicall,
    universal_router_execute: UniversalRouterExecute,
    // Phase 2 routers: returned only by `decodeFor` with the matching router,
    // never by `decode`. See routers.zig.
    aerodrome_swap_exact_tokens_for_tokens: routers.AerodromeExactIn,
    aerodrome_swap_exact_eth_for_tokens: routers.AerodromeEthExactIn,
    aerodrome_swap_exact_tokens_for_eth: routers.AerodromeExactIn,
    aerodrome_unsafe_swap_exact_tokens_for_tokens: routers.AerodromeUnsafe,
    aerodrome_swap_exact_tokens_for_tokens_fot: routers.AerodromeExactIn,
    aerodrome_swap_exact_eth_for_tokens_fot: routers.AerodromeEthExactIn,
    aerodrome_swap_exact_tokens_for_eth_fot: routers.AerodromeExactIn,
    slipstream_exact_input_single: routers.SlipstreamExactInputSingle,
    slipstream_exact_output_single: routers.SlipstreamExactOutputSingle,
    /// Path hops carry `int24` tick spacing; read it with `Hop.tickSpacing()`.
    slipstream_exact_input: V3ExactInput,
    /// Path hops carry `int24` tick spacing; read it with `Hop.tickSpacing()`.
    slipstream_exact_output: V3ExactOutput,
    camelot_v2_swap_exact_tokens_for_tokens_fot: routers.CamelotV2ExactIn,
    camelot_v2_swap_exact_eth_for_tokens_fot: routers.CamelotV2EthExactIn,
    camelot_v2_swap_exact_tokens_for_eth_fot: routers.CamelotV2ExactIn,
    camelot_v3_exact_input_single: routers.AlgebraExactInputSingle,
    camelot_v3_exact_input_single_fot: routers.AlgebraExactInputSingle,
    camelot_v3_exact_input: routers.AlgebraExactInput,
    camelot_v3_exact_output: routers.AlgebraExactOutput,
    pancake_exact_input_stable_swap: routers.PancakeStableExactIn,
    pancake_exact_output_stable_swap: routers.PancakeStableExactOut,
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
    /// The rules inner calls are decoded with: the router the multicall was
    /// sent to (`decodeFor`), `.uniswap` for `decode`.
    router: routers.Router = .uniswap,

    pub fn len(self: Multicall) usize {
        return self.calls.len();
    }

    pub fn iterator(self: Multicall) Iterator {
        return .{ .calls = self.calls };
    }

    /// One inner call. Inner swaps and the router's payment/permit helpers
    /// are decoded; everything else (including a nested multicall or
    /// Universal Router execute) is `.other`.
    pub const Call = union(enum) {
        swap: Decoded,
        payment: Payment,
        other: struct {
            selector: [4]u8,
            data: []const u8,
        },
    };

    /// SwapRouter/SwapRouter02 helper calls (PeripheryPayments*, SelfPermit).
    /// A null `recipient` means the overload without one (SwapRouter02
    /// extended: pays `msg.sender`).
    pub const Payment = union(enum) {
        /// unwrapWETH9(uint256[,address])
        unwrap_weth9: struct { amount_minimum: u256, recipient: ?[20]u8 },
        /// unwrapWETH9WithFee(uint256,[address,]uint256,address)
        unwrap_weth9_with_fee: struct { amount_minimum: u256, recipient: ?[20]u8, fee_bips: u256, fee_recipient: [20]u8 },
        /// sweepToken(address,uint256[,address])
        sweep_token: struct { token: [20]u8, amount_minimum: u256, recipient: ?[20]u8 },
        /// sweepTokenWithFee(address,uint256,[address,]uint256,address)
        sweep_token_with_fee: struct { token: [20]u8, amount_minimum: u256, recipient: ?[20]u8, fee_bips: u256, fee_recipient: [20]u8 },
        /// refundETH()
        refund_eth,
        /// wrapETH(uint256)
        wrap_eth: struct { value: u256 },
        /// pull(address,uint256)
        pull: struct { token: [20]u8, value: u256 },
        self_permit: SelfPermit,
    };

    /// selfPermit / selfPermitIfNecessary (EIP-2612: `amount` is the value,
    /// `deadline` the deadline) and selfPermitAllowed /
    /// selfPermitAllowedIfNecessary (DAI-style: `amount` is the nonce,
    /// `deadline` the expiry).
    pub const SelfPermit = struct {
        kind: enum { permit, permit_if_necessary, allowed, allowed_if_necessary },
        token: [20]u8,
        amount: u256,
        deadline: u256,
        v: u8,
        r: [32]u8,
        s: [32]u8,
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

/// Which command table a Universal Router deployment uses. The same command
/// byte means different things on different deployments.
pub const UrDialect = enum {
    /// Uniswap UR with V4 (Commands.sol @ a9c574f): type mask 0x7f, 0x10
    /// V4_SWAP, 0x21 EXECUTE_SUB_PLAN. What `decode` assumes.
    uniswap,
    /// Pre-V4 Uniswap UR (Commands.sol @ v1.6.0 41183d6, e.g. 0x3fC91A3a…7FAD):
    /// type mask 0x3f, same 0x00-0x0e commands, 0x10-0x20 and 0x22 are NFT and
    /// approval commands (`.other`), 0x21 EXECUTE_SUB_PLAN.
    uniswap_v1,
    /// PancakeSwap UR on BSC: type mask 0x3f, same 0x00-0x0e commands, 0x22 /
    /// 0x23 stable swaps (layout confirmed by BSC tx 0x6cf50c46…c803). 0x10
    /// carries a PancakeSwap Infinity plan with its own pool key and is
    /// `.other`, as is every other command.
    pancake,
};

/// Universal Router `execute`. `deadline` is null for `execute(bytes,bytes[])`
/// and for a sub-plan.
pub const UniversalRouterExecute = struct {
    /// One byte per command.
    commands: []const u8,
    /// One ABI-encoded input per command; `inputs.len() == commands.len`.
    inputs: BytesArray,
    deadline: ?u256,
    dialect: UrDialect = .uniswap,
    /// True for an EXECUTE_SUB_PLAN payload. Sub-plans nest one level: a
    /// sub-plan command inside a sub-plan is `.other`.
    is_sub_plan: bool = false,

    pub fn iterator(self: UniversalRouterExecute) Iterator {
        return .{ .commands = self.commands, .inputs = self.inputs, .dialect = self.dialect, .is_sub_plan = self.is_sub_plan };
    }

    pub const Iterator = struct {
        commands: []const u8,
        inputs: BytesArray,
        dialect: UrDialect = .uniswap,
        is_sub_plan: bool = false,
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
///
/// The Dispatcher maps two recipient sentinels before use: `0x0…01` means
/// `msg.sender` and `0x0…02` means the router itself (Dispatcher.sol:332-340).
/// `decode` does not resolve the sentinel; every `recipient` field below
/// carries the raw 20-byte value from calldata.
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
        /// Raw sentinel from calldata: `0x0…01` maps to `msg.sender` and
        /// `0x0…02` to the router itself (Dispatcher.map); `decode` does not
        /// resolve it.
        recipient: [20]u8,
        amount_in: u256,
        amount_out_min: u256,
        path: V3Path,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    /// Same layout as `V3SwapExactIn`; `path` is reversed (token out first).
    pub const V3SwapExactOut = struct {
        /// Raw sentinel from calldata: `0x0…01` maps to `msg.sender` and
        /// `0x0…02` to the router itself (Dispatcher.map); `decode` does not
        /// resolve it.
        recipient: [20]u8,
        amount_out: u256,
        amount_in_max: u256,
        path: V3Path,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    pub const V2SwapExactIn = struct {
        /// Raw sentinel from calldata: `0x0…01` maps to `msg.sender` and
        /// `0x0…02` to the router itself (Dispatcher.map); `decode` does not
        /// resolve it.
        recipient: [20]u8,
        amount_in: u256,
        amount_out_min: u256,
        path: AddressPath,
        payer_is_user: bool,
        min_hop_price_x36: ?U256Array,
    };

    pub const V2SwapExactOut = struct {
        /// Raw sentinel from calldata: `0x0…01` maps to `msg.sender` and
        /// `0x0…02` to the router itself (Dispatcher.map); `decode` does not
        /// resolve it.
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

    /// Permit2 `PermitDetails`.
    pub const PermitDetails = struct {
        token: [20]u8,
        amount: u160,
        expiration: u48,
        nonce: u48,
    };

    /// An ABI `PermitDetails[]` (static tuples, 4 words each), borrowed from
    /// calldata; every element was validated.
    pub const PermitDetailsArray = struct {
        words: []const u8,

        pub fn len(self: PermitDetailsArray) usize {
            _ = self;
            @panic("todo");
        }

        pub fn get(self: PermitDetailsArray, i: usize) PermitDetails {
            _ = self;
            _ = i;
            @panic("todo");
        }
    };

    /// Permit2 `AllowanceTransferDetails`.
    pub const AllowanceTransfer = struct {
        from: [20]u8,
        to: [20]u8,
        amount: u160,
        token: [20]u8,
    };

    /// An ABI `AllowanceTransferDetails[]` (static tuples, 4 words each).
    pub const AllowanceTransferArray = struct {
        words: []const u8,

        pub fn len(self: AllowanceTransferArray) usize {
            _ = self;
            @panic("todo");
        }

        pub fn get(self: AllowanceTransferArray, i: usize) AllowanceTransfer {
            _ = self;
            _ = i;
            @panic("todo");
        }
    };

    /// PERMIT2_PERMIT (0x0a): `(PermitSingle, bytes signature)`.
    pub const Permit2Permit = struct {
        details: PermitDetails,
        spender: [20]u8,
        sig_deadline: u256,
        signature: []const u8,
    };

    /// PERMIT2_PERMIT_BATCH (0x03): `(PermitBatch, bytes signature)`.
    pub const Permit2PermitBatch = struct {
        details: PermitDetailsArray,
        spender: [20]u8,
        sig_deadline: u256,
        signature: []const u8,
    };

    /// PancakeSwap UR stable swap (0x22 exact in / 0x23 exact out).
    /// `amount0`/`amount1` are amountIn/amountOutMin for exact in and
    /// amountOut/amountInMax for exact out. `flags[i]` selects the stable
    /// pool for hop i.
    pub const StableSwap = struct {
        recipient: [20]u8,
        amount0: u256,
        amount1: u256,
        path: AddressPath,
        flags: U256Array,
        payer_is_user: bool,
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
        /// `amount` is the portion with 1e18 = 100%.
        pay_portion_full_precision: TokenRecipientAmount,
        /// BALANCE_CHECK_ERC20 (0x0e).
        balance_check_erc20: struct { owner: [20]u8, token: [20]u8, min_balance: u256 },
        permit2_permit: Permit2Permit,
        permit2_permit_batch: Permit2PermitBatch,
        /// PERMIT2_TRANSFER_FROM (0x02).
        permit2_transfer_from: struct { token: [20]u8, recipient: [20]u8, amount: u160 },
        /// PERMIT2_TRANSFER_FROM_BATCH (0x0d).
        permit2_transfer_from_batch: AllowanceTransferArray,
        /// V4_SWAP (0x10, `.uniswap` dialect only).
        v4_swap: v4.Plan,
        /// EXECUTE_SUB_PLAN: a nested `execute` with `deadline == null` and
        /// `is_sub_plan == true`.
        execute_sub_plan: UniversalRouterExecute,
        /// PancakeSwap 0x22 (`.pancake` dialect only).
        stable_swap_exact_in: StableSwap,
        /// PancakeSwap 0x23 (`.pancake` dialect only).
        stable_swap_exact_out: StableSwap,
        /// Any other command type (position managers, NFT commands, ...),
        /// undecoded.
        other: struct {
            command_type: u8,
            input: []const u8,
        },
    };
};

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
        selU32(selectors.swap_exact_tokens_for_tokens_02) => Decoded{ .swap_router02_swap_exact_tokens_for_tokens = parseV2ExactIn(data, args_base, false) orelse return null },
        selU32(selectors.swap_tokens_for_exact_tokens_02) => Decoded{ .swap_router02_swap_tokens_for_exact_tokens = parseV2ExactOut(data, args_base, false) orelse return null },
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

/// Like `decode`, but Universal Router `execute` calldata is read with the
/// given command table. `decode(data)` is `decodeWithUrDialect(data, .uniswap)`.
pub fn decodeWithUrDialect(data: []const u8, dialect: UrDialect) ?Decoded {
    _ = dialect;
    return decode(data);
}

/// Decode a batch call (`multicall` or Universal Router `execute`) sent to
/// `router`: the multicall's `router` field is set so inner calls decode under
/// its rules, and `execute` uses the router's `UrDialect`. Null for any other
/// selector. Used by `decodeFor`.
pub fn decodeBatchFor(router: Router, data: []const u8) ?Decoded {
    _ = router;
    _ = data;
    return null;
}

/// Router-aware decoding for routers whose selectors collide with Uniswap's
/// but mean something else (Slipstream, Camelot, Pancake, pre-V4 UR).
pub const decodeFor = routers.decodeFor;
pub const Router = routers.Router;
pub const Protocol = routers.Protocol;
pub const Deployment = routers.Deployment;
pub const routerAt = routers.routerAt;

/// Decode router calldata. Returns null for unknown selectors and for any
/// malformed or truncated input; never panics and never allocates.
pub fn decode(data: []const u8) ?Decoded {
    return decodeDispatch(data, true);
}
