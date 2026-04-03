# LayerZero-v2 Bug Bounty Findings

**Program:** Immunefi LayerZero-v2 ($250K-$15M for critical)
**Scope:** Theft or permanent locking of user funds
**Started:** 2026-04-02

---

## Critical Findings

### [CRITICAL-1] Payload Overwrite via Grace Period + Reverification (AV3+AV6)

**Status:** SUBMISSION READY  
**Submission:** `SUBMISSION_1_GracePeriodFundTheft.md`  
**Audit reports checked:** All 7 EndpointV2 + 3 DVN audits — **NOT a known issue**

**Files:**
- `protocol/contracts/EndpointV2.sol:151-160` (verify)
- `protocol/contracts/MessagingChannel.sol:37-46` (_inbound)
- `protocol/contracts/MessageLibManager.sol:108-135` (isValidReceiveLibrary)

**Impact:** Direct theft of user funds. An attacker with access to a deprecated (but still valid during grace period) receive library's DVN quorum can overwrite the payloadHash of a legitimately verified message, redirecting cross-chain token transfers to the attacker's address.

**PoCs:**
- `test/audit/06_GracePeriod.t.sol::test_AV6_3_PayloadOverwriteViaGracePeriod` (basic overwrite)
- `test/audit/09_GracePeriodFundTheft.t.sol::test_CRITICAL_GracePeriodFundTheft` (full fund theft with ERC20)
- `test/audit/09_GracePeriodFundTheft.t.sol::test_CRITICAL_VictimCannotRecover` (nilify/burn cannot recover)

**Root cause chain:**
1. Grace period creates dual-library validity: `isValidReceiveLibrary()` returns true for both old and new libraries during the grace period window.
2. Re-verification allowed: `_verifiable()` permits re-verification when `inboundPayloadHash != EMPTY_PAYLOAD_HASH`.
3. Unconditional overwrite: `_inbound()` writes the new payloadHash without checking for an existing non-empty entry.

**Attack flow:**
1. Protocol upgrades receive library from LibA to LibB with grace period G
2. User's cross-chain transfer verified by LibB with `payloadHash = H_legit`
3. Attacker (controlling LibA's DVN quorum) calls LibA.commitVerification with same nonce but `payloadHash = H_attack`
4. LibA still valid during grace period → `EndpointV2.verify()` accepts → `_inbound()` overwrites H_legit with H_attack
5. `lzReceive()` with legitimate message reverts (hash mismatch) — permanent fund loss
6. Attacker executes crafted message — tokens transferred to attacker
7. Neither nilify nor burn can restore the original hash

**Prerequisites:**
- Receive library upgrade with grace period > 0 blocks (routine operation)
- Control of DVN quorum on the OLD library (weaker post-upgrade)
- Target message verified but not yet executed (common during congestion)

**Recommendation:**
`_inbound()` should reject writes when a non-empty hash already exists:
```solidity
if (inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] != EMPTY_PAYLOAD_HASH)
    revert Errors.LZ_PayloadHashAlreadyExists();
```

---

### [CRITICAL-2] Nilify Bypass via Re-Verification Renders Precrime Ineffective (AV10)

**Status:** SUBMISSION READY  
**Submission:** `SUBMISSION_2_NilifyBypass.md`  
**Audit reports checked:** All 7 EndpointV2 + 3 DVN audits — **NOT a known issue**

**Files:**
- `protocol/contracts/EndpointV2.sol:344-352` (_verifiable)
- `protocol/contracts/MessagingChannel.sol:37-46` (_inbound)
- `protocol/contracts/MessagingChannel.sol:95-105` (nilify)

**Impact:** Precrime protection bypass leading to fund theft. An OApp's nilification of a malicious message can be silently undone by the receive library calling verify() again on the nilified nonce. No grace period or second library required.

**PoCs:**
- `test/audit/10_NilifyUnnilification.t.sol::test_CRITICAL_NilifyBypassViaReverification` (full fund theft)
- `test/audit/10_NilifyUnnilification.t.sol::test_NilifyStatePersistence` (nilify undone with original hash)
- `test/audit/10_NilifyUnnilification.t.sol::test_NilPayloadHashPassesVerifiableCheck` (root cause isolation)

**Root cause:**
1. `nilify()` sets `inboundPayloadHash` to `NIL_PAYLOAD_HASH` (0xff...ff)
2. `_verifiable()` only blocks re-verification when stored hash == `EMPTY_PAYLOAD_HASH` (0x00)
3. `NIL_PAYLOAD_HASH != EMPTY_PAYLOAD_HASH`, so `_verifiable()` returns true for nilified nonces
4. `_inbound()` unconditionally overwrites NIL with the attacker's payload hash

**Attack flow:**
1. Malicious message verified by receive library
2. OApp detects via Precrime and calls nilify() — slot becomes NIL_PAYLOAD_HASH
3. Attacker (controlling DVN quorum) re-verifies same nonce with malicious payload
4. NIL overwritten → message is executable again → tokens stolen

**Key distinction from CRITICAL-1:** No grace period needed. A single compromised library suffices.

**Recommendation:**
Add NIL_PAYLOAD_HASH check in `_verifiable()`:
```solidity
bytes32 existingHash = inboundPayloadHash[_receiver][_origin.srcEid][_origin.sender][_origin.nonce];
if (existingHash == NIL_PAYLOAD_HASH) return false;
```

---

## High Findings

_None yet._

## Medium Findings

_None yet._

---

## Investigated — Not Exploitable

### AV7: Compose Chain Reentrancy
**Result:** Safe by design. `lzCompose` stamps `RECEIVED_MESSAGE_HASH` before external call. Cross-function reentrancy through `lzReceive`, `sendCompose`, `clear`, `skip`, and `verify` all analyzed — no exploitable path found. `sendContext` modifier prevents `send()` reentrancy. All state changes complete before external calls (CEI pattern).

---

## Observations (Not Vulnerabilities)

### DVN Overlap in Required/Optional Lists (AV1.3)
The UlnConfig struct explicitly allows overlap between requiredDVNs and optionalDVNs. An OApp setting required=1 + optional=1/1 with the same DVN may believe they have 2-DVN security but actually have 1-DVN effective security. This is documented behavior.

### Verify Selector Skips Replay Protection (AV2.2)
`_shouldCheckHash` returns false for `verify.selector`, meaning verify calls through `DVN.execute()` have no replay protection. This is by design since verify is idempotent, but a DVN could downgrade its own verification by re-calling verify with 0 confirmations.

### usedHash Reset on Failed Execution (AV2.3 / AV8.2)
When `DVN.execute()` fails, `usedHashes[hash]` is reset to false, allowing the same instruction to be retried. This is intentional for operational recovery but creates a TOCTOU window.
