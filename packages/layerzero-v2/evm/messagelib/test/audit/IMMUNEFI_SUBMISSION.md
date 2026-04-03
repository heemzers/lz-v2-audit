# Immunefi Bug Report: Permanent Fund Locking via Grace Period + Reverification

## Bug Description

A critical vulnerability exists in the interaction between `EndpointV2.verify()`, `MessagingChannel._inbound()`, and `MessageLibManager.isValidReceiveLibrary()` that allows permanent locking of user funds during a receive library upgrade with a grace period.

### Root Cause

`MessagingChannel._inbound()` (line 45) performs an **unconditional assignment** to `inboundPayloadHash[receiver][srcEid][sender][nonce]`:

```solidity
function _inbound(address _receiver, uint32 _srcEid, bytes32 _sender, uint64 _nonce, bytes32 _payloadHash) internal {
    if (_payloadHash == EMPTY_PAYLOAD_HASH) revert Errors.LZ_InvalidPayloadHash();
    inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash; // OVERWRITES without checking existing value
}
```

Combined with:
1. `_verifiable()` (EndpointV2.sol:344-352) allows re-verification of already-verified-but-unexecuted messages
2. `isValidReceiveLibrary()` (MessageLibManager.sol:108-135) validates BOTH old and new receive libraries during a grace period

### Attack Flow

**Prerequisites:**
- A default receive library upgrade is performed with `gracePeriod > 0`
- Attacker controls the DVN quorum on the OLD (deprecated) receive library
- A legitimate message has been verified by the NEW library but not yet executed

**Steps:**
1. Admin calls `setDefaultReceiveLibrary(srcEid, newLib, gracePeriod)` to upgrade the receive library
2. During the grace period, both old and new libraries pass `isValidReceiveLibrary()` check
3. A legitimate cross-chain message (e.g., OFT token transfer of 100 ETH) is verified by the new library's DVN quorum, storing `payloadHashA` at nonce N
4. Before execution, attacker uses the old library (still valid during grace period) to call `verify()` for the same nonce N with a different `payloadHashB`
5. `_inbound()` unconditionally overwrites `payloadHashA` with `payloadHashB`
6. `lzReceive()` for the original message reverts with `LZ_PayloadHashNotFound` because `keccak256(originalPayload) != payloadHashB`

**Result:** The original message can NEVER execute. All recovery paths fail:
- `lzReceive(originalMessage)` - reverts (hash mismatch)
- `clear(originalMessage)` - reverts (hash mismatch)
- `nilify(originalHash)` - reverts (stored hash is malicious, not original)
- `burn(originalHash)` - reverts (stored hash is malicious, not original)
- `skip()` - only works for the next unverified nonce

Tokens burned/locked on the source chain during the original `send()` can never be credited on the destination chain.

## Impact

**Permanent locking of user funds.** Any cross-chain value transfer (OFT token bridges, cross-chain swaps, etc.) that has been verified but not yet executed can be permanently blocked during a library upgrade grace period. The attacker needs:
1. Control of the DVN quorum on the deprecated library (which may have weaker security assumptions since it's being replaced)
2. A library upgrade with a non-zero grace period (standard operational procedure)

In production:
- LayerZero OFT bridges lock/burn tokens on the source chain when sending
- If the destination-side message is blocked, those tokens are permanently locked
- There is no refund mechanism on the source chain
- The endpoint owner's `recoverToken()` cannot recover ERC20s locked in application contracts

The impact scales with the number of pending (verified-but-unexecuted) messages during the grace period window. A single attacker can target multiple messages across multiple OApps simultaneously.

## Risk Breakdown

- **Difficulty:** Medium (requires compromised DVN quorum on deprecated library)
- **Weakness:** Design flaw (unconditional overwrite in _inbound)
- **CVSS:** 9.1 (Critical) - Integrity: High, Availability: High
- **Category:** Theft/permanent locking of unclaimed yield or user funds

## Recommendation

Any of the following fixes would prevent this attack:

1. **Preferred:** `_inbound()` should reject overwrites of existing non-empty hashes:
```solidity
function _inbound(..., bytes32 _payloadHash) internal {
    if (_payloadHash == EMPTY_PAYLOAD_HASH) revert Errors.LZ_InvalidPayloadHash();
    bytes32 existing = inboundPayloadHash[_receiver][_srcEid][_sender][_nonce];
    if (existing != EMPTY_PAYLOAD_HASH) revert Errors.LZ_PayloadHashAlreadyExists();
    inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash;
}
```

2. **Alternative:** `verify()` should track which library originally verified a nonce and reject re-verification from a different library.

3. **Alternative:** Grace period validation should exclude re-verification of nonces that were verified by a different library.

## Proof of Concept

### Running the PoC

```bash
cd packages/layerzero-v2/evm/messagelib
forge test --match-test test_CRITICAL_PermanentFundLocking -vvv
```

### PoC File

`test/audit/09_CriticalPoC.t.sol` contains three tests:

1. **`test_CRITICAL_PermanentFundLocking()`** - Full attack flow demonstrating:
   - MockOFT receiver tracking 100 ETH token credit
   - Legitimate message verified by new library
   - Old library overwrites payload during grace period
   - lzReceive reverts, all 4 recovery paths fail
   - Permanent fund locking confirmed

2. **`test_ROOTCAUSE_InboundOverwritesExistingHash()`** - Isolates the root cause: `_inbound()` unconditionally overwrites existing non-empty hashes

3. **`test_PREREQUISITE_NoGracePeriodPreventsAttack()`** - Confirms zero grace period prevents the attack (old library immediately invalid)

### Test Output

```
[PASS] test_CRITICAL_PermanentFundLocking() (gas: 488762)
Logs:
  === PAYLOAD OVERWRITE CONFIRMED ===
    Original hash : 0x682df258a17932b16354180b7893884adcd9587f867609ee5fce18a2054a3897
    Malicious hash: 0x8f55852a14a9f8731668d57f6858a6561c543548870c215275d437a62f98c355
    lzReceive with original message: REVERTED
    clear() with original message: REVERTED
    nilify() with original hash: REVERTED
    burn() with original hash: REVERTED
  ========================================
    PERMANENT FUND LOCKING CONFIRMED
  ========================================
    Locked amount (wei): 100000000000000000000
    Victim: 0x000000000000000000000000000000000000bEEF
    lzReceive: REVERTS | clear: REVERTS
    nilify: REVERTS | burn: REVERTS
    Source chain tokens: PERMANENTLY LOCKED
  ========================================
```

### Vulnerable Code References

| File | Line | Function | Issue |
|------|------|----------|-------|
| `protocol/contracts/MessagingChannel.sol` | 45 | `_inbound()` | Unconditional overwrite of `inboundPayloadHash` |
| `protocol/contracts/EndpointV2.sol` | 349-351 | `_verifiable()` | Allows re-verification of verified-but-unexecuted messages |
| `protocol/contracts/EndpointV2.sol` | 152 | `verify()` | `isValidReceiveLibrary` accepts both old and new during grace period |
| `protocol/contracts/MessageLibManager.sol` | 108-135 | `isValidReceiveLibrary()` | Grace period makes both libraries valid |
