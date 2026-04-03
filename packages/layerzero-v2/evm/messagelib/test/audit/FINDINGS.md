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

## Critical/High Findings

### [CRITICAL] LzToken Front-Running Theft via _suppliedLzToken() Race Condition (AV4.1)

**Files:**
- `protocol/contracts/EndpointV2.sol:287-289` (_suppliedLzToken)
- `protocol/contracts/EndpointV2.sol:244-260` (_payToken)

**Impact:** Direct theft of user lzToken funds. Any lzTokens sitting in the EndpointV2 contract can be stolen by a front-running attacker.

**PoC:** `test/audit/04_FeeExploit.t.sol::test_AV4_1_LzTokenFrontRunningTheft` (PASSING)

**Description:**
`_suppliedLzToken(true)` returns `IERC20(lzToken).balanceOf(address(this))` - the entire lzToken balance of the endpoint, not what the current sender deposited. When a user transfers lzToken to the endpoint before calling `send()`, an attacker can front-run the `send()` call. The attacker's `send()` sees the victim's tokens as "supplied", pays the fee from them, and receives the remainder as a refund to the attacker's address. The victim's subsequent `send()` reverts with `LZ_ZeroLzTokenFee`.

**Attack flow:**
1. Victim transfers 10 lzToken to EndpointV2 (preparing to send a message)
2. Attacker front-runs: calls `send(payInLzToken=true)` with 0 lzToken of their own
3. `_suppliedLzToken()` returns 10 (victim's tokens)
4. Endpoint sends 1 lzToken fee to SendLib, refunds 9 to attacker's refundAddress
5. Victim's `send()` reverts - balance is 0
6. Victim permanently loses 10 lzToken (9 to attacker, 1 to SendLib as fee)

**Note:** The `Transfer.token()` function uses `safeTransfer` (not `safeTransferFrom`), confirming the transfer-then-send pattern is the expected flow, making this race window inherent.

**Severity justification:** This is a permissionless attack requiring no trust assumption violation. Any user paying lzToken fees is vulnerable. The attacker needs only to monitor the mempool and front-run.

**Recommendation:**
- Use `transferFrom` pattern instead of pre-transfer + balanceOf
- Track per-sender deposits in a mapping
- Use a pull-based fee model where the endpoint pulls exact amounts from the sender

---

### [HIGH] NIL_CONFIRMATIONS Disables Block Finality Checks for OApp Configs (AV1.3)

**Files:**
- `messagelib/contracts/uln/UlnBase.sol:82-85` (config resolution)
- `messagelib/contracts/uln/ReceiveUlnBase.sol:48-57` (_verified)
- `messagelib/contracts/uln/UlnBase.sol:62` (default config guard)

**Impact:** Complete bypass of block confirmation requirements. An OApp delegate can disable all finality checks, allowing DVN verifications with 0 confirmations to pass.

**PoC:** `test/audit/01_QuorumBypass.t.sol::test_AV1_3_NilConfirmations_OAppConfig_DisablesConfirmationCheck` (PASSING)

**Description:**
When `confirmations = type(uint64).max` (NIL_CONFIRMATIONS), the config resolution in `getUlnConfig()` does nothing for that field, leaving `rtnConfig.confirmations = 0` (struct zero-initialization). This makes `_verified()` check `verification.confirmations >= 0` which is ALWAYS TRUE for any uint64.

The asymmetry: `setDefaultUlnConfigs()` correctly rejects NIL_CONFIRMATIONS (line 62), but OApp-level `setConfig()` does NOT. A delegate authorized via `setDelegate()` can set this config freely.

Combined with `NIL_DVN_COUNT`, an attacker can create a config requiring only 1 optional DVN with 0 confirmations - the weakest possible verification.

**Recommendation:**
- Add a guard in `_setConfig()` or `_setUlnConfig()` to reject `NIL_CONFIRMATIONS` for OApp configs, or
- `_verified()` should require `_requiredConfirmation >= 1` as a floor

---

### [HIGH] DVN Confirmation Downgrade via verify() Overwrite (AV2.1)

**Files:**
- `messagelib/contracts/uln/ReceiveUlnBase.sol:44` (_verify)
- `messagelib/contracts/uln/dvn/DVN.sol:386-392` (_shouldCheckHash)

**Impact:** A compromised DVN operator can permanently stall message delivery by retracting their verification. This is a liveness attack that can block any packet in any N-of-M quorum.

**PoC:** `test/audit/02_SignatureReplay.t.sol::test_AV2_2_ConfirmationDowngradeBlocksDelivery` (PASSING)

**Description:**
`_verify()` performs an unconditional overwrite: `hashLookup[...][...][msg.sender] = Verification(true, _confirmations)`. It does NOT take `max(old, new)`. A DVN that verified with 15 confirmations can call verify again with 0, and `_verified()` will return false (0 < 1 required).

Additionally, `_shouldCheckHash()` returns false for the verify selector, meaning there is NO replay protection. The DVN can call verify unlimited times with any confirmation value.

In a 2-of-2 quorum: DVN1 verifies -> DVN2 verifies -> DVN1 retracts to 0 -> `commitVerification` reverts. DVN1 has permanently vetoed the message.

**Recommendation:**
- `_verify()` should use `max(existing.confirmations, _confirmations)` instead of unconditional overwrite
- Or: once a verification is committed, prevent re-verification of the same packet

---

### [MEDIUM] Treasury Over-Withdrawal of LzToken Fees (AV4.2)

**Files:**
- `messagelib/contracts/SendLibBaseE2.sol:77-86` (withdrawLzTokenFee)
- `messagelib/contracts/SendLibBase.sol:43,136` (fees mapping - native only)

**Impact:** Treasury owner can drain the entire lzToken balance of any SendLib with no accounting check. The `fees` mapping only tracks native fees.

**PoC:** `test/audit/04_FeeExploit.t.sol::test_AV4_2_TreasuryOverWithdrawal` (PASSING)

**Note:** This requires treasury owner access, making it a centralization/trust risk rather than a permissionless attack. However, the lack of any accounting for lzToken fees is a design gap.

---

### [MEDIUM] Delegate Chain Attack: Security Config Downgrade (AV5.5)

**Files:**
- `protocol/contracts/EndpointV2.sol:327-330` (setDelegate)
- `protocol/contracts/EndpointV2.sol:355-357` (_assertAuthorized)

**Impact:** A compromised delegate can disable all security properties of an OApp's receive path by combining NIL_CONFIRMATIONS with minimal DVN quorum.

**PoC:** `test/audit/05_AccessControl.t.sol::test_AV5_5_DelegateWeakensSecurityViaNilConfirmations` (PASSING)

**Note:** Requires compromised delegate. The protocol intentionally grants delegates full config power. The finding is that this power includes security-critical config changes with no time-lock or scoping mechanism.

---

## Observations (Not Vulnerabilities)

### DVN Overlap in Required/Optional Lists (AV1.3)
The UlnConfig struct explicitly allows overlap between requiredDVNs and optionalDVNs. An OApp setting required=1 + optional=1/1 with the same DVN may believe they have 2-DVN security but actually have 1-DVN effective security. This is documented behavior.

### LzToken Change Orphans Accumulated Fees (AV4.4)
When `setLzToken()` changes the token, lzTokens accumulated in SendLib under the old address are stranded with no automatic recovery. Only manual treasury intervention via `withdrawLzTokenFee(oldAddress, ...)` can recover them.

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
