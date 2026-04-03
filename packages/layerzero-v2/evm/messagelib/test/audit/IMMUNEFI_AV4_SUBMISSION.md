# Immunefi Bug Bounty Submission — LayerZero v2

## Title

Critical: lzToken Front-Running Attack Enables Permanent Theft of User Funds in EndpointV2.send()

## Severity

**Critical** — Direct theft of user funds with no access control requirement

## Target

**Project:** LayerZero v2
**Scope:** `protocol/contracts/EndpointV2.sol`, `protocol/contracts/EndpointV2Alt.sol`

---

## Vulnerability Summary

`EndpointV2._suppliedLzToken()` measures how much lzToken a sender supplied by reading `IERC20(lzToken).balanceOf(address(this))`. This is a shared global balance that reflects all lzToken held by the endpoint contract, not the amount deposited by the current caller.

Because the protocol requires a two-step flow — users pre-transfer lzToken to the endpoint before calling `send()` — any attacker who monitors the mempool can front-run a victim's deposit, inflate the apparent "supplied" balance with their own tokens, and cause the endpoint to refund the victim's tokens to the attacker via the excess-refund logic in `_payToken()`. The victim's tokens are permanently lost and there is no permissionless recovery path.

`EndpointV2Alt._suppliedNative()` contains the identical pattern for the alt-native ERC20 token, meaning the same attack surface exists on every alt-token chain for every message regardless of fee currency.

---

## Bug Location

| File | Function | Lines |
|------|----------|-------|
| `protocol/contracts/EndpointV2.sol` | `_suppliedLzToken()` | 287–297 |
| `protocol/contracts/EndpointV2.sol` | `_payToken()` | 244–260 |
| `protocol/contracts/EndpointV2Alt.sol` | `_suppliedNative()` | 39–41 |

---

## Root Cause

The vulnerable measurement in `_suppliedLzToken()`:

```solidity
// EndpointV2.sol lines 287-297 (vulnerable)
function _suppliedLzToken(bool _payInLzToken) internal view returns (uint256 supplied) {
    if (_payInLzToken) {
        supplied = IERC20(lzToken).balanceOf(address(this));
        // if the _lzToken fee is an ERC20, we will use the balance of the endpoint
        // to determine the fee
        if (supplied == 0) revert Errors.LZ_ZeroLzTokenFee();
    }
}
```

`balanceOf(address(this))` returns the aggregate lzToken balance of the contract across all concurrent depositors. There is no per-sender accounting. When `_payToken()` computes the refund as `supplied - required`, it sends the excess to the current caller's `_refundAddress`, not to the original depositor:

```solidity
// EndpointV2.sol lines 244-260 (vulnerable)
function _payToken(
    address _token,
    uint256 _required,
    uint256 _supplied,
    address _receiver,
    address _refundAddress
) internal {
    if (_required > 0) {
        IERC20(_token).safeTransfer(_receiver, _required);
    }
    uint256 refund = _supplied - _required;
    if (refund > 0) {
        IERC20(_token).safeTransfer(_refundAddress, refund);
    }
}
```

The combination of shared-balance measurement and caller-directed refund is the complete attack primitive.

---

## Attack Flow

### Single-Victim Attack

1. **Victim (Alice)** transfers `X` lzToken to the endpoint as the first step of the two-step send flow.
2. **Attacker** monitors the mempool and observes Alice's deposit transaction.
3. **Attacker** transfers `R` lzToken to the endpoint, where `R` equals the fee required for a valid message of their own.
4. **Attacker** front-runs Alice's `send()` call by submitting `send(payInLzToken=true, refundAddress=attacker)` with a higher gas price.
5. Inside the attacker's `send()`:
   - `_suppliedLzToken()` returns `X + R` (the full endpoint balance, including Alice's deposit)
   - `_payToken()` forwards `R` to the SendLib as the fee
   - `_payToken()` refunds `X + R - R = X` to the attacker's `_refundAddress`
6. The endpoint lzToken balance is now `0`.
7. Alice's `send()` transaction executes and reverts with `LZ_ZeroLzTokenFee` — her `X` tokens have been transferred to the attacker.
8. Alice has no permissionless recovery path. `recoverToken` is `onlyOwner`.

### Multi-Victim Scaling

The attacker can batch-steal from multiple concurrent victims in a single transaction. Each victim pre-deposited an amount `X_i`. The attacker's total cost is only one protocol fee `R`, while their profit equals `sum(X_i) - R`.

---

## Proof of Concept

**Test files:**
- `test/audit/04_FeeExploit.t.sol` — contains tests AV4_3, AV4_7, AV4_8, AV4_9

**Run command:**
```bash
forge test --match-path test/audit/04_FeeExploit.t.sol -vv
```

**Measured output:**

```
=== FUND THEFT QUANTIFICATION ===
Alice deposit (lost): 5000000000000000000  (5 ether)
Attacker fee cost:    1000000000000000000  (1 ether)
Attacker NET PROFIT:  4000000000000000000  (4 ether)
Profit ratio:         5x

=== MULTI-VICTIM BATCH THEFT ===
Total stolen from 3 victims: 12000000000000000000  (12 ether)
Attacker cost:                1000000000000000000   (1 ether)
Attacker NET PROFIT:         11000000000000000000  (11 ether)
```

---

## Impact

| Property | Assessment |
|----------|------------|
| Fund loss type | Permanent — victim tokens transferred to attacker |
| Access control required | None — any EOA can execute the attack |
| Precondition | Attacker must observe victim's deposit in the mempool |
| Attack cost | One protocol fee `R` (attacker's own message fee) |
| Victim loss | Entire pre-deposited lzToken amount |
| Multi-victim scaling | Yes — single attacker tx drains multiple deposits |
| Recovery mechanism | None permissionless; `recoverToken` is `onlyOwner` |
| Chains affected (alt-token) | All chains using `EndpointV2Alt`, every message |

The attack is economically rational whenever a victim's deposit exceeds the protocol fee for a minimal message. Given that cross-chain messages can carry arbitrary fee amounts, the profit-to-cost ratio is bounded only by victim deposit sizes.

On chains using `EndpointV2Alt`, the same `balanceOf` pattern in `_suppliedNative()` means the vulnerability applies to the alt-native token for every single message, not only for explicit lzToken-paying messages. This effectively doubles the attack surface.

---

## Affected Components

1. **`EndpointV2._suppliedLzToken()`** — uses `balanceOf(address(this))` instead of per-sender tracking. The inline comment at line 291 ("we will use the balance of the endpoint to determine the fee") confirms this is an intentional design decision, but the security consequences of shared-balance measurement in a concurrent environment were not accounted for.

2. **`EndpointV2._payToken()`** — refunds excess tokens to the current caller's `_refundAddress` rather than to the original depositor. When the "supplied" amount has been inflated by a third-party deposit, this becomes a direct transfer to an unauthorized recipient.

3. **`EndpointV2Alt._suppliedNative()`** — contains the identical `balanceOf` pattern for the alt-native ERC20 token. Any chain deploying `EndpointV2Alt` is vulnerable on every message.

---

## Why This Is Not a Known Issue

- The `balanceOf` pattern is used intentionally; the code comment at line 291 documents it as the chosen design.
- The `setLzToken` guard at line 295 (which reverts on zero balance) defends only against wrong-token configuration, not against shared-balance front-running.
- Ten prior audit reports were reviewed. None document this front-running vector or the interaction between the shared-balance measurement and the caller-directed refund in `_payToken()`.
- The two-step transfer model (pre-deposit then call `send()`) is standard practice for protocols that cannot call `transferFrom` in the same transaction, but it is precisely this pattern that creates the mempool-observable window of vulnerability.

---

## Recommended Fix

Replace the `balanceOf(address(this))` measurement with an `approve` + `transferFrom` pattern. This ties the supplied amount to the specific caller and eliminates the shared-balance attack surface entirely.

```solidity
// Before (vulnerable):
function _suppliedLzToken(bool _payInLzToken) internal view returns (uint256 supplied) {
    if (_payInLzToken) {
        supplied = IERC20(lzToken).balanceOf(address(this));
        if (supplied == 0) revert Errors.LZ_ZeroLzTokenFee();
    }
}

// After (fixed):
function _suppliedLzToken(bool _payInLzToken, uint256 _amount) internal returns (uint256 supplied) {
    if (_payInLzToken) {
        if (_amount == 0) revert Errors.LZ_ZeroLzTokenFee();
        IERC20(lzToken).safeTransferFrom(msg.sender, address(this), _amount);
        supplied = _amount;
    }
}
```

The caller passes the intended fee amount explicitly. The `transferFrom` in the same atomic call eliminates the pre-deposit window and makes it impossible for a third party to inflate the measured balance.

The same fix applies to `EndpointV2Alt._suppliedNative()`:

```solidity
// Before (vulnerable):
function _suppliedNative() internal view returns (uint256 supplied) {
    supplied = IERC20(nativeToken).balanceOf(address(this));
}

// After (fixed):
function _suppliedNative(uint256 _amount) internal returns (uint256 supplied) {
    if (_amount == 0) revert Errors.LZ_ZeroNativeTokenFee();
    IERC20(nativeToken).safeTransferFrom(msg.sender, address(this), _amount);
    supplied = _amount;
}
```

---

## Disclosure Timeline

| Event | Date |
|-------|------|
| Vulnerability discovered | [DATE] |
| PoC developed and confirmed | [DATE] |
| Submission to Immunefi | [DATE] |
| Target | LayerZero Labs via Immunefi |

---

## References

- `protocol/contracts/EndpointV2.sol` lines 244–260, 287–297
- `protocol/contracts/EndpointV2Alt.sol` lines 39–41
- `test/audit/04_FeeExploit.t.sol` (PoC test suite)
