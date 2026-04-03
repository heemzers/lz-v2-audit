# Nilify Bypass via Re-Verification Renders Precrime Protection Ineffective

## Bug Description

When an OApp calls `nilify()` to block a suspicious message (e.g., after Precrime detects a malicious payload), the `inboundPayloadHash` slot is set to `NIL_PAYLOAD_HASH` (`bytes32(type(uint256).max)`). However, the receive library can subsequently call `EndpointV2.verify()` on the same nonce with any payload hash, and `_inbound()` unconditionally overwrites `NIL_PAYLOAD_HASH`. This is because `_verifiable()` only checks that the stored hash is not `EMPTY_PAYLOAD_HASH` (bytes32(0)) — since `NIL_PAYLOAD_HASH` is not zero, the check passes. The nilification is silently undone, and the message becomes executable again.

## Impact

- **Precrime bypass**: The entire `nilify()` mechanism — designed to let OApps block suspicious messages before execution — is unreliable. A compromised or malicious receive library can undo any nilification at any time.
- **Fund theft**: If an OApp uses Precrime to detect and nilify a malicious cross-chain transfer, the attacker (controlling the library's DVN quorum) can re-verify the same nonce with the same malicious payload, causing token theft.
- **Single library sufficiency**: Unlike the grace period attack (Submission 1), this does NOT require a library upgrade or grace period. A single compromised receive library is sufficient.
- **Scope**: All OApps that rely on `nilify()` for security (specifically those using the Precrime framework) are affected.

## Risk Breakdown

- **Difficulty**: Medium — Requires compromising the DVN quorum of the current receive library. This is a higher bar than the grace period attack but still realistic for libraries with weak quorum configurations.
- **Prerequisites**: (1) OApp uses nilify() as a security mechanism. (2) Attacker controls the DVN quorum. (3) Target nonce has been nilified but not burned.
- **Window**: Permanent — the nilification can be undone at any time as long as the nonce has not been burned.

## Root Cause

1. **`_verifiable()` does not account for NIL state** (`EndpointV2.sol:344-352`): The condition `inboundPayloadHash[...][nonce] != EMPTY_PAYLOAD_HASH` treats NIL_PAYLOAD_HASH the same as any verified hash, allowing re-verification of nilified nonces.

2. **`_inbound()` unconditionally overwrites** (`MessagingChannel.sol:45`): No check for NIL_PAYLOAD_HASH before overwriting.

## Recommendation

Add a check in either `_verifiable()` or `_inbound()` to reject writes to slots holding `NIL_PAYLOAD_HASH`:

```solidity
// Option A: in _verifiable()
function _verifiable(Origin calldata _origin, address _receiver, uint64 _lazyInboundNonce) internal view returns (bool) {
    bytes32 existingHash = inboundPayloadHash[_receiver][_origin.srcEid][_origin.sender][_origin.nonce];
    if (existingHash == NIL_PAYLOAD_HASH) return false;  // nilified nonces cannot be re-verified
    return _origin.nonce > _lazyInboundNonce || existingHash != EMPTY_PAYLOAD_HASH;
}

// Option B: in _inbound()
function _inbound(address _receiver, uint32 _srcEid, bytes32 _sender, uint64 _nonce, bytes32 _payloadHash) internal {
    if (_payloadHash == EMPTY_PAYLOAD_HASH) revert Errors.LZ_InvalidPayloadHash();
    if (inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] == NIL_PAYLOAD_HASH) 
        revert Errors.LZ_NilifiedNonceCannotBeReverified();
    inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash;
}
```

## Proof of Concept

**File**: `test/audit/10_NilifyUnnilification.t.sol`
**Run**: `forge test --match-test test_CRITICAL_NilifyBypassViaReverification -vvv`

### Test: `test_CRITICAL_NilifyBypassViaReverification`

1. **Setup**: Deploy full V2 stack, MockOFTReceiver holding 50,000 tokens.
2. **Verify malicious message**: DVN verifies nonce 1 with payload `(attacker, 50000e18)`.
3. **OApp nilifies**: `nilify()` sets slot to `NIL_PAYLOAD_HASH`. Execution attempt reverts.
4. **Attacker re-verifies**: Same library's DVN verifies nonce 1 again with the malicious payload. `_verifiable()` returns true (NIL != EMPTY), `_inbound()` overwrites NIL.
5. **Execute**: Malicious message executes. 50,000 tokens stolen.

### Test: `test_NilPayloadHashPassesVerifiableCheck`

Isolates the root cause: directly asserts that `EndpointV2.verifiable()` returns `true` for a nilified nonce, proving the guard condition is insufficient.

## References

- `EndpointV2.sol:344-352` — `_verifiable()` failing to block nilified nonces
- `MessagingChannel.sol:10-11` — `EMPTY_PAYLOAD_HASH` vs `NIL_PAYLOAD_HASH` constants
- `MessagingChannel.sol:37-46` — `_inbound()` unconditional overwrite
- `MessagingChannel.sol:95-105` — `nilify()` function
