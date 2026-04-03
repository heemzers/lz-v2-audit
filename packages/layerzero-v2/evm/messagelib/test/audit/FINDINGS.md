# LayerZero-v2 Bug Bounty Findings

**Program:** Immunefi LayerZero-v2 ($250K-$15M for critical)
**Scope:** Theft or permanent locking of user funds
**Started:** 2026-04-02

---

## Critical Findings

### [CRITICAL] Payload Overwrite via Grace Period + Reverification (AV3+AV6)

**Files:**
- `protocol/contracts/EndpointV2.sol:151-160` (verify)
- `protocol/contracts/MessagingChannel.sol:37-46` (_inbound)
- `protocol/contracts/MessageLibManager.sol:108-135` (isValidReceiveLibrary)

**Impact:** Permanent locking/loss of user funds. An attacker with access to a deprecated (but still valid during grace period) receive library's DVN quorum can overwrite the payloadHash of a legitimately verified message, making the original message permanently unexecutable.

**PoC (discovery):** `test/audit/06_GracePeriod.t.sol::test_AV6_3_PayloadOverwriteViaGracePeriod`
**PoC (submission-ready):** `test/audit/09_CriticalPoC.t.sol::test_CRITICAL_PermanentFundLocking`

**Description:**
1. During a receive library upgrade with a grace period, BOTH old and new libraries are valid callers of `EndpointV2.verify()`
2. `_verifiable()` (line 344-352) allows re-verification of already-verified-but-unexecuted messages (the `inboundPayloadHash != EMPTY_PAYLOAD_HASH` condition passes)
3. `_inbound()` (line 45) unconditionally OVERWRITES the `inboundPayloadHash` with the new value
4. This means: new library verifies message A -> old library re-verifies same nonce with different payloadHash B -> original message A can never execute

**Attack flow:**
1. Legitimate message verified by new library with `payloadHashA`
2. Before execution, attacker uses old library (still valid in grace period) to verify same nonce with `payloadHashB`
3. `inboundPayloadHash` is overwritten from A to B
4. `lzReceive()` for original message fails (hash mismatch)
5. User funds encoded in message A are permanently locked

**Prerequisites:**
- A receive library upgrade with grace period > 0 blocks
- Control of the DVN quorum on the OLD (deprecated) library
- Target message must be verified but not yet executed

**Recovery Path Analysis:**
All endpoint recovery functions fail for the original message after overwrite:
- `lzReceive()` reverts with `LZ_PayloadHashNotFound` (hash mismatch)
- `clear()` reverts with `LZ_PayloadHashNotFound` (hash mismatch)
- `nilify(originalHash)` reverts (stored hash is malicious, not original)
- `burn(originalHash)` reverts (stored hash is malicious, not original)
- `skip()` only works for the next unverified nonce, cannot help

The OApp admin can nilify/burn using the malicious hash to "clean up" the slot, but the original message data is permanently lost. Tokens burned/locked on the source chain can never be credited on the destination chain.

**Recommendation:**
- `_inbound()` should NOT overwrite existing non-empty payload hashes, or
- `verify()` should reject re-verification from a different library than the one that originally verified, or
- Grace period validation should exclude re-verification of already-verified nonces

---

## High Findings

_None yet._

## Medium Findings

_None yet._

---

## Observations (Not Vulnerabilities)

### DVN Overlap in Required/Optional Lists (AV1.3)
The UlnConfig struct explicitly allows overlap between requiredDVNs and optionalDVNs. An OApp setting required=1 + optional=1/1 with the same DVN may believe they have 2-DVN security but actually have 1-DVN effective security. This is documented behavior.

### Verify Selector Skips Replay Protection (AV2.2)
`_shouldCheckHash` returns false for `verify.selector`, meaning verify calls through `DVN.execute()` have no replay protection. This is by design since verify is idempotent, but a DVN could downgrade its own verification by re-calling verify with 0 confirmations.

### usedHash Reset on Failed Execution (AV2.3 / AV8.2)
When `DVN.execute()` fails, `usedHashes[hash]` is reset to false, allowing the same instruction to be retried. This is intentional for operational recovery but creates a TOCTOU window.

---

## Finding Template

### [SEVERITY] Title

**File:** `path/to/file.sol:LINE`
**Impact:** Description of impact
**PoC:** `test/audit/XX_Name.t.sol::test_functionName`

**Description:**
...

**Recommendation:**
...
