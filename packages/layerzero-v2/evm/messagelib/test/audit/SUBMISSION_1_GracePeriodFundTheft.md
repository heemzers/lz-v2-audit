# Payload Overwrite via Grace Period Reverification Enables Permanent Fund Theft

## Bug Description

During a receive library upgrade that uses a grace period, `MessageLibManager.isValidReceiveLibrary()` accepts both the old and new receive libraries simultaneously. This allows the old library to call `EndpointV2.verify()` for nonces already verified by the new library. Since `MessagingChannel._inbound()` (line 45) unconditionally overwrites `inboundPayloadHash` without checking for existing non-empty entries, the old library can silently replace a legitimate payload hash with an attacker-controlled one. The legitimate cross-chain message becomes permanently unexecutable, and the attacker's crafted payload can be executed instead.

## Impact

- **Direct theft of user funds**: Any cross-chain token transfer (OFT, ONFT, or custom OApp) that is verified but not yet executed during a library upgrade window can have its payload hash silently overwritten. The attacker's crafted payload redirects the tokens to the attacker's address.
- **Permanent fund locking**: Even if the attacker does not execute their crafted payload, the legitimate message can never be executed because its hash no longer matches what is stored in the endpoint.
- **Scope**: All OApps using the default receive library are affected during any library upgrade that uses a grace period. This is a routine operational procedure.
- **No OApp misconfiguration required**: The vulnerability is in the core protocol (`EndpointV2.verify` + `MessagingChannel._inbound` + `MessageLibManager.isValidReceiveLibrary`).

## Risk Breakdown

- **Difficulty**: Medium — Requires compromising the DVN quorum of the OLD (deprecated) library. Post-upgrade, the old library's DVN set may have weaker security guarantees (that's often why the upgrade happened). A single compromised DVN in a 1-of-1 quorum suffices.
- **Prerequisites**: (1) Receive library upgrade with grace period > 0. (2) Control of DVN quorum on the old library. (3) Target message must be verified but not yet executed (common during network congestion).
- **Window**: The entire grace period duration (set by the endpoint owner or OApp). Can be hundreds or thousands of blocks.

## Root Cause

Three design decisions combine to create this vulnerability:

1. **Grace period creates dual-library validity** (`MessageLibManager.sol:108-135`): `isValidReceiveLibrary()` returns `true` for both the current library and the old library during the grace period. Both can call `EndpointV2.verify()`.

2. **Re-verification is allowed** (`EndpointV2.sol:344-352`): `_verifiable()` permits re-verification of any nonce where `inboundPayloadHash != EMPTY_PAYLOAD_HASH`. This is intentional for single-library scenarios but creates a payload substitution attack when two libraries are simultaneously valid.

3. **Unconditional overwrite** (`MessagingChannel.sol:37-46`): `_inbound()` writes `inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash` without checking whether a non-empty hash already exists. There is no append-only or first-writer-wins semantics.

## Recommendation

**Option A (minimal fix)**: In `_inbound()`, reject writes when a non-empty hash already exists:
```solidity
function _inbound(address _receiver, uint32 _srcEid, bytes32 _sender, uint64 _nonce, bytes32 _payloadHash) internal {
    if (_payloadHash == EMPTY_PAYLOAD_HASH) revert Errors.LZ_InvalidPayloadHash();
    if (inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] != EMPTY_PAYLOAD_HASH) 
        revert Errors.LZ_PayloadHashAlreadyExists();
    inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash;
}
```

**Option B (targeted fix)**: In `verify()`, reject re-verification from a library different from the one that originally verified:
```solidity
// Track which library verified each nonce
mapping(address => mapping(uint32 => mapping(bytes32 => mapping(uint64 => address)))) public verifyingLib;

function verify(Origin calldata _origin, address _receiver, bytes32 _payloadHash) external {
    if (!isValidReceiveLibrary(_receiver, _origin.srcEid, msg.sender)) revert Errors.LZ_InvalidReceiveLibrary();
    // ... existing checks ...
    address existingLib = verifyingLib[_receiver][_origin.srcEid][_origin.sender][_origin.nonce];
    if (existingLib != address(0) && existingLib != msg.sender) revert Errors.LZ_DifferentVerifyingLib();
    verifyingLib[_receiver][_origin.srcEid][_origin.sender][_origin.nonce] = msg.sender;
    _inbound(_receiver, _origin.srcEid, _origin.sender, _origin.nonce, _payloadHash);
}
```

## Proof of Concept

The PoC deploys a full LayerZero v2 stack, creates a mock OFT receiver holding 100,000 ERC20 tokens, and demonstrates end-to-end fund theft via the grace period payload overwrite.

**File**: `test/audit/09_GracePeriodFundTheft.t.sol`
**Run**: `forge test --match-test test_CRITICAL_GracePeriodFundTheft -vvv`

### Test: `test_CRITICAL_GracePeriodFundTheft`

1. **Setup**: Deploy EndpointV2, old ReceiveUln302, new ReceiveUln302, MockOFTReceiver with 100,000 tokens. Upgrade receive library with 100-block grace period.
2. **Legitimate verification**: New library's DVN verifies nonce 1 with payload `(victim, 100000e18)`. Hash stored correctly.
3. **Attacker overwrite**: Old library's DVN (still valid during grace period) verifies nonce 1 with payload `(attacker, 100000e18)`. Old library calls `commitVerification` → `EndpointV2.verify()` → `_inbound()` silently overwrites the hash.
4. **Legitimate execution blocked**: `lzReceive` with the legitimate message reverts with `LZ_PayloadHashNotFound`.
5. **Attacker executes**: `lzReceive` with the malicious message succeeds. 100,000 tokens transferred to attacker.
6. **Final state**: attacker balance = 100,000, victim balance = 0, OFT receiver = 0.

### Test: `test_CRITICAL_VictimCannotRecover`

Demonstrates that after the overwrite:
- `nilify(maliciousHash)` blocks the attacker but does NOT restore the legitimate hash. Victim's funds remain permanently locked.
- `burn()` reverts because `lazyInboundNonce` has not advanced past the nonce.
- Neither recovery mechanism can restore the original payload hash.

## References

- `EndpointV2.sol:151-161` — `verify()` function
- `EndpointV2.sol:344-352` — `_verifiable()` allowing re-verification
- `MessagingChannel.sol:37-46` — `_inbound()` unconditional overwrite
- `MessageLibManager.sol:108-135` — `isValidReceiveLibrary()` grace period logic
- `MessageLibManager.sol:171-194` — `setDefaultReceiveLibrary()` with grace period
