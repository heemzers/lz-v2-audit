# Immunefi Bug Bounty Submission — LayerZero v2

## Title

High: DVN Shared-VID Signature Replay Halves Effective Quorum Without OApp Awareness

## Severity

**High** — Subverts cross-chain message verification security model

## Target

**Project:** LayerZero v2
**Scope:**
- `messagelib/contracts/uln/dvn/DVN.sol`
- `messagelib/contracts/uln/ReceiveUlnBase.sol`

---

## Vulnerability Summary

The DVN multisig system contains three distinct issues that together allow the effective security quorum of a cross-chain message to be silently halved, governance signatures to be replayed across chains, and a DVN operator to toggle message deliverability after verification is complete.

The root cause of the first two issues is that `DVN.hashCallData()` constructs the signed payload as:

```solidity
keccak256(abi.encodePacked(_vid, _target, _expiration, _callData))
```

This hash does not include `block.chainid` or `address(this)`. Because `vid` has no on-chain uniqueness enforcement, two DVN contracts that share the same `vid` and signer set will produce identical signed hashes for the same instruction. Combined with `_shouldCheckHash()` returning `false` for verify selectors — which disables the `usedHashes` replay guard entirely — the same set of signer signatures can be submitted on multiple DVN instances to satisfy independent quorum checks.

The third issue is in `ReceiveUlnBase._verify()`, which performs a plain assignment when storing confirmations rather than taking the maximum of the old and new values. Because verify selectors also bypass `usedHashes`, a DVN can re-submit with a lower confirmation count after a valid high-confirmation verification, downgrading the stored value and blocking delivery.

---

## Bug Locations

| File | Function | Lines | Issue |
|------|----------|-------|-------|
| `messagelib/contracts/uln/dvn/DVN.sol` | `hashCallData()` | 376 | Missing `chain_id` and `address(this)` in hash |
| `messagelib/contracts/uln/dvn/DVN.sol` | `_shouldCheckHash()` | 386–392 | Verify selectors bypass `usedHashes` replay protection |
| `messagelib/contracts/uln/ReceiveUlnBase.sol` | `_verify()` | 44 | Unconditional overwrite of stored confirmations |

---

## Root Cause

### Issue 1: Shared-VID Double Verification (HIGH)

`hashCallData()` in `DVN.sol` line 376:

```solidity
function hashCallData(
    uint32 _vid,
    address _target,
    bytes calldata _callData,
    uint256 _expiration
) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(_vid, _target, _expiration, _callData));
}
```

The hash includes `_vid`, `_target`, `_expiration`, and `_callData`, but neither `block.chainid` nor `address(this)`. The `vid` (version ID) is an operator-assigned `uint32` with no global uniqueness registry. If two DVN contracts — deployed on the same chain and configured as separate required DVNs by an OApp — share the same `vid` and signer set, any signed message is valid on both contracts simultaneously.

An OApp that sets `requiredDVNs = [dvnA, dvnB]` expects 2-of-2 independent DVN verifications. If `dvnA.vid == dvnB.vid` and both share the same quorum threshold and signer addresses, a single signing event produces signatures accepted by both contracts. The OApp's security reduces from 2-of-2 to 1-of-1 without any on-chain signal that this has occurred.

This does not require compromised keys. It is a structural architectural gap: two legitimate operators running identical software can end up with shared vids, and the protocol has no mechanism to detect or prevent this.

### Issue 2: Cross-Chain Signature Replay (MEDIUM)

Because `chain_id` is absent from `hashCallData()`, a signature generated for a DVN on chain A is cryptographically identical to what would be required for the same DVN (same `vid`, same signers) on chain B. This affects both governance calls (e.g., `setSigner`, `setQuorum`) and verify calls.

Practical impact:

- A quorum rotation applied on chain A can be replayed on chain B against a DVN that shares the same `vid`, undoing the rotation on the second chain without any new signing.
- A signer that has been removed from a DVN on chain A may still hold valid signatures that satisfy the old quorum on chain B.
- Verify instructions targeting a `ReceiveUln302` address that exists at the same address on multiple chains are portable across all of them.

Submission of signatures on the target chain requires `ADMIN_ROLE`, which limits the exploitability window. However, the signatures themselves require no new signing — any entity with `ADMIN_ROLE` on chain B can replay captured signatures from chain A.

### Issue 3: Confirmation Downgrade via Verify Replay (MEDIUM)

`ReceiveUlnBase._verify()` stores verification results with a plain assignment:

```solidity
// ReceiveUlnBase.sol line 44 (vulnerable)
hashLookup[keccak256(_packetHeader)][_payloadHash][msg.sender] =
    Verification(true, _confirmations);
```

This unconditionally overwrites any previously stored `Verification` for the same `(packetHeader, payloadHash, dvn)` triple. Because `_shouldCheckHash()` returns `false` for verify selectors, the `usedHashes` guard does not apply and the same DVN can call `verify()` for the same message any number of times with different confirmation counts.

A DVN operator who initially verified with `confirmations = 20` (making the message deliverable) can later call `verify()` again with `confirmations = 0`, overwriting the stored value. `_checkVerifiable()` then sees 0 stored confirmations against a required minimum of, say, 15 and blocks `commitVerification()`. The operator can toggle deliverability arbitrarily until the message is executed. This requires DVN operator compromise (signers plus admin), but the window is unbounded in time — there is no deadline after which a submitted verification becomes immutable.

---

## Proof of Concept

Test file: `test/audit/02_SignatureReplay.t.sol`

Run with:

```
forge test --match-path "*audit/02*" -vv
```

### AV2-2: Shared-VID Double Verification

```
CONFIRMED: Shared-vid DVNs allow double-verification with single signing
OApp believes it has 2-of-2 DVN security, but only 1 signing was needed
Impact: Effective quorum halved without OApp awareness
```

Two DVN instances are deployed with the same `vid` (e.g., `vid = 1`) and identical signer sets. The OApp configures `requiredDVNs = [dvnA, dvnB]`. A single set of signatures — generated once by the shared signer set — is submitted to both `dvnA` and `dvnB`. Both contracts accept the signatures and call `verify()`. `_checkVerifiable()` sees both DVNs as having attested and allows `commitVerification()` to proceed. The OApp's intended 2-of-2 requirement is satisfied by 1 independent signing event.

### AV2-5: Cross-Chain/Cross-DVN Signature Replay

```
CONFIRMED: Cross-chain/cross-DVN signature replay succeeds
Same signatures work on both DVN instances due to missing chain_id in hash
```

Signatures constructed for `dvnA` with `vid = 1` are submitted to `dvnB` (also `vid = 1`, same signers, same chain or different chain). Both contracts compute the same hash and verify the same signatures. No new signing is required.

### AV2-6: Confirmation Downgrade

```
CONFIRMED: DVN can toggle message deliverability via confirmation downgrade
1. DVN verifies with 20 confirmations (message deliverable)
2. DVN re-verifies with 0 confirmations (delivery BLOCKED)
3. DVN re-verifies with 20 again (delivery restored)
```

The DVN calls `verify()` three times for the same `(packetHeader, payloadHash)` pair. Each call overwrites the stored `Verification`. Step 2 blocks delivery by writing `confirmations = 0`. Step 3 restores it. The DVN operator holds indefinite control over whether the message can be committed.

---

## Impact

### Issue 1 — Shared-VID Double Verification

Severity: **High**

An OApp that deploys or selects two DVNs believing they are independent security providers may receive no additional security benefit if those DVNs share a `vid`. The effective quorum required to forge or selectively deliver messages is halved: only 1 DVN's signers need to cooperate rather than 2. For OApps using DVNs as their sole security mechanism (the default for most LayerZero deployments), this represents a direct reduction in the security guarantee advertised by the protocol.

This is a silent failure: no event is emitted, no revert occurs, and no monitoring tool can detect the shared-vid condition unless it independently audits every configured DVN's `vid` field.

### Issue 2 — Cross-Chain Signature Replay

Severity: **Medium**

Governance actions signed for one chain can be applied to another chain without new signing. In particular, quorum reductions or signer removals that are signed for a decommissioning chain can be used to alter the configuration of a production chain with no additional coordination from the DVN signers. The attack requires an on-chain submitter with `ADMIN_ROLE` on the target chain, which constrains exploitability but does not eliminate it — compromised or malicious infrastructure operators can replay governance signatures silently.

### Issue 3 — Confirmation Downgrade

Severity: **Medium**

A compromised DVN operator can selectively block individual messages without any on-chain indicator. The operator first verifies the message normally (ensuring the message eventually delivers), then re-verifies with 0 confirmations to block delivery, effectively censoring specific cross-chain messages while maintaining the appearance of normal DVN operation. This enables targeted, deniable message censorship.

---

## Recommended Fixes

### Fix 1: Bind `hashCallData()` to chain and contract identity

```solidity
// DVN.sol — hashCallData() (line 376)
function hashCallData(
    uint32 _vid,
    address _target,
    bytes calldata _callData,
    uint256 _expiration
) public view returns (bytes32) {
    return keccak256(abi.encodePacked(block.chainid, address(this), _vid, _target, _expiration, _callData));
}
```

Adding `block.chainid` prevents cross-chain replay. Adding `address(this)` prevents cross-DVN replay on the same chain even when `vid` values collide. Note this changes the function from `pure` to `view`.

### Fix 2: Guard `_verify()` with a max-confirmations check

```solidity
// ReceiveUlnBase.sol — _verify() (line 44)
function _verify(bytes calldata _packetHeader, bytes32 _payloadHash, uint64 _confirmations) internal {
    bytes32 headerHash = keccak256(_packetHeader);
    Verification storage existing = hashLookup[headerHash][_payloadHash][msg.sender];
    if (!existing.submitted || _confirmations > existing.confirmations) {
        hashLookup[headerHash][_payloadHash][msg.sender] = Verification(true, _confirmations);
    }
}
```

This ensures that a DVN can increase its attested confirmation count but never decrease it. Once a message is verifiable, it remains verifiable regardless of subsequent calls to `verify()` with lower confirmation values.

### Fix 3: Enforce or document `vid` uniqueness

Option A (on-chain): Require DVN constructors to register their `vid` against `address(this)` in a shared registry contract. Reject registration if the `(vid, chainid)` pair is already occupied by a different address.

Option B (documentation): Prominently document in the DVN deployment guide that `vid` must be unique per chain. Provide a public registry or tooling that allows OApps to verify that no two of their configured required DVNs share a `vid` before trusting the multi-DVN security model.

---

## Trust Assumption Analysis

| Issue | Requires Compromised Keys | Requires Admin Role | Requires On-Chain Action by Attacker |
|-------|--------------------------|--------------------|------------------------------------|
| 1 — Shared-VID Double Verification | No | No | Yes (DVN operators submit verify calls normally) |
| 2 — Cross-Chain Signature Replay | No (old/captured signatures suffice) | Yes (`ADMIN_ROLE` on target chain) | Yes |
| 3 — Confirmation Downgrade | Yes (DVN signers + admin) | Yes | Yes |

Issue 1 is the most severe because it requires no compromise at all. Two DVNs operating correctly and in good faith can silently provide weaker security than the OApp intends, purely due to an undetected `vid` collision.

Issue 2 escalates if the `ADMIN_ROLE` is held by infrastructure that also processed the original chain's governance — a realistic scenario for DVN operators managing multi-chain deployments from shared tooling.

Issue 3 requires full DVN operator compromise, which places it in the same threat category as a rogue DVN, but the confirmation-downgrade vector is a distinct and previously undocumented capability that a rogue operator gains.

---

## Additional Notes

The `_shouldCheckHash()` logic was presumably added to avoid storage overhead on the hot `verify()` path. However, the consequence is that verify calls have no replay protection at all — not even single-chain replay protection. The recommended fix for Issue 1 reduces the cost of replay by making captured signatures useless on any chain or DVN other than the one they were generated for. The `usedHashes` guard could then optionally be extended to verify selectors as a defense-in-depth measure without significantly impacting gas costs.

The combination of Issue 1 and Issue 2 is particularly concerning for DVN operators who manage deployments across many chains from a single signer set. A shared `vid` across all deployments — a natural outcome if the `vid` is hardcoded in the DVN implementation — means that any signature generated anywhere in the operator's network is valid everywhere.
