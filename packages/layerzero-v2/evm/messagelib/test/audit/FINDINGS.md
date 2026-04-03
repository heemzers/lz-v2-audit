# LayerZero-v2 Bug Bounty Findings

**Program:** Immunefi LayerZero-v2 ($250K-$15M for critical)
**Scope:** Theft or permanent locking of user funds
**Started:** 2026-04-02
**Updated:** 2026-04-03 (session 3)

---

## Critical Findings

### [CRITICAL] Payload Overwrite via Grace Period + Reverification (AV3+AV6)

**Status:** SUBMITTED to Immunefi
**Files:**
- `protocol/contracts/EndpointV2.sol:151-160` (verify)
- `protocol/contracts/MessagingChannel.sol:37-46` (_inbound)
- `protocol/contracts/MessageLibManager.sol:108-135` (isValidReceiveLibrary)

**Impact:** Permanent locking/loss of user funds. An attacker with access to a deprecated (but still valid during grace period) receive library's DVN quorum can overwrite the payloadHash of a legitimately verified message, making the original message permanently unexecutable.

**PoC (discovery):** `test/audit/06_GracePeriod.t.sol::test_AV6_3_PayloadOverwriteViaGracePeriod`
**PoC (submission-ready):** `test/audit/09_CriticalPoC.t.sol::test_CRITICAL_PermanentFundLocking`

**Root Cause:** `_inbound()` (MessagingChannel.sol:45) unconditionally overwrites `inboundPayloadHash` with no check whether the slot already contains a different hash. Combined with grace period allowing two libraries to call `verify()`, this enables payload replacement.

---

## High Findings

### [HIGH] Delegate Config Retroactivity - Payload Overwrite Without Grace Period (AV5+AV1)

**Files:**
- `protocol/contracts/EndpointV2.sol:355-357` (_assertAuthorized)
- `messagelib/contracts/uln/uln302/ReceiveUln302.sol:48-61` (commitVerification)
- `messagelib/contracts/uln/UlnBase.sol:79-85` (getUlnConfig - NIL_CONFIRMATIONS resolution)
- `messagelib/contracts/uln/ReceiveUlnBase.sol:43-46` (_verify - unconditional overwrite)

**Impact:** Permanent fund loss via payload overwrite. A compromised delegate can:
1. Change the OApp's DVN set to include a malicious DVN
2. Set NIL_CONFIRMATIONS (resolves to 0 block confirmations)
3. Use the malicious DVN to re-verify with a different payload hash
4. Re-commit, overwriting the legitimate payload hash

This is a SEPARATE attack path from AV3+AV6 because it does NOT require a grace period or library upgrade. It exploits the config retroactivity: ULN config is read at `commitVerification()` time, not at DVN verification time.

**PoC:**
- `test/audit/05_AccessControl.t.sol::test_AV5_6_PayloadOverwriteViaConfigChangeAndReverify` (hash overwrite)
- `test/audit/05_AccessControl.t.sol::test_AV5_11_EndToEndFundLoss` (full fund loss: lzReceive reverts + all recovery paths fail)

**Attack Flow:**
1. Legitimate message verified and committed by honest DVNs
2. Compromised delegate calls `setConfig()` to swap required DVNs to a malicious DVN + set NIL_CONFIRMATIONS
3. Malicious DVN calls `verify(header, malicious_payloadHash, 0)`
4. `commitVerification(header, malicious_payloadHash)` succeeds because:
   - `getUlnConfig()` reads the CURRENT (weakened) config
   - `_checkVerifiable()` checks malicious DVN with 0 confirmations requirement
   - `0 >= 0` passes
5. `_inbound()` overwrites `inboundPayloadHash` from legitimate to malicious
6. Original message can never be executed

**Prerequisites:**
- Compromised delegate (set by OApp via `setDelegate()`)
- Target message must be committed but not yet executed (verified but pending lzReceive)

**Why This Is HIGH (Not Just an Observation):**
- Delegates are meant for configuration convenience, but the protocol provides NO timelock or rate-limiting on config changes
- Config changes apply RETROACTIVELY to already-submitted DVN signatures (no snapshot at verify time)
- The `_inbound()` unconditional overwrite enables permanent fund loss through config manipulation
- A delegate compromise is a single-key compromise, not a multi-sig/quorum breach

**Recommendation:**
- `_inbound()` should reject overwriting an existing non-empty hash from the SAME receive library (different library during grace period is AV3+AV6, same library via config change is this finding)
- Or: add a timelock/delay mechanism for ULN config changes that affect the DVN set or confirmations
- Or: snapshot the config at DVN verify time and use that snapshot during commitVerification

### [HIGH] Config Retroactivity - Delegate Weakens Security After DVN Verification (AV5.5)

**Files:** Same as above

**Impact:** Delegate can retroactively reduce the security guarantees that DVNs provided. DVNs verify under a 3-of-3/20-confirmation config, but a compromised delegate changes to 1-of-1/0-confirmation before `commitVerification()`. The commit succeeds under the weakened config.

**PoC:** `test/audit/05_AccessControl.t.sol::test_AV5_5_ConfigRetroactivity_DelegateWeakensBeforeCommit`

**Note:** This is the same root cause as the payload overwrite above but demonstrates the quorum reduction angle rather than the payload overwrite angle.

### [MEDIUM-HIGH] Delegate Nilify-Skip-Burn - Permanent Message Destruction (AV5.7)

**Files:**
- `protocol/contracts/MessagingChannel.sol:95-105` (nilify - sets hash to NIL_PAYLOAD_HASH)
- `protocol/contracts/MessagingChannel.sol:82-88` (skip - advances lazyInboundNonce)
- `protocol/contracts/MessagingChannel.sol:112-121` (burn - deletes hash permanently)
- `protocol/contracts/EndpointV2.sol:355-357` (_assertAuthorized - delegate has full power)

**Impact:** A compromised delegate can permanently destroy a verified-but-not-yet-executed message by chaining three protocol operations: nilify (changes hash to NIL_PAYLOAD_HASH), skip (advances lazyInboundNonce past the target nonce), burn (deletes the hash entirely). After burn, the nonce can never be re-verified because `_verifiable()` requires either `nonce > lazyInboundNonce` (fails: nonce <= lazyInboundNonce) or `hash != EMPTY` (fails: hash was deleted). The original cross-chain message is permanently lost.

**PoC:** `test/audit/05_AccessControl.t.sol::test_AV5_7_DelegateNilifySkipBurn_PermanentDestruction`

**Attack Flow:**
1. Legitimate message committed at nonce 1 (hash stored in endpoint)
2. Delegate calls `nilify(oapp, srcEid, sender, 1, payloadHash)` - hash becomes NIL_PAYLOAD_HASH
3. Delegate calls `skip(oapp, srcEid, sender, 2)` - advances lazyInboundNonce to 2
4. Delegate calls `burn(oapp, srcEid, sender, 1, NIL_PAYLOAD_HASH)` - deletes hash permanently
5. Nonce 1 is permanently dead: `_verifiable()` returns false, no re-verification possible

**Why This Matters:** Unlike the config retroactivity attack (AV5.6), this path requires NO external DVN deployment. The delegate uses only built-in protocol operations (nilify, skip, burn) in their intended sequence, but the cumulative effect is permanent message destruction. Each operation individually is an intended delegate capability; the concern is that a single-key compromise enables irreversible damage with no timelock or rate-limiting.

**Mitigating factor:** Nilify, skip, and burn are designed delegate powers. This is a trust model concern (delegate has too much instant, untimelocked power) rather than a logic bug.

### [MEDIUM] Config Changes Persist After Delegate Revocation (AV5.9)

**Files:**
- `messagelib/contracts/uln/UlnBase.sol:151-185` (_setUlnConfig — writes persist independently of delegate status)
- `protocol/contracts/EndpointV2.sol:327-330` (setDelegate — only changes delegate mapping, not configs)

**Impact:** When an OApp owner detects delegate compromise and revokes the delegate via `setDelegate(address(0))`, all config changes previously made by the delegate persist. The weakened ULN config (e.g., malicious DVN + 0 confirmations) remains active and exploitable until the OApp owner manually restores the config. Config persistence is expected key-value-store behavior, but the operational gap is that revoking a delegate provides false security if the owner doesn't also manually audit and restore all configs.

**PoC:** `test/audit/05_AccessControl.t.sol::test_AV5_9_ConfigPersistsAfterDelegateRevocation`

**Mitigating factor:** OApp owner CAN manually restore configs. This is an operational awareness gap, not a protocol logic bug. Strengthens the AV5.6 case by demonstrating that delegate revocation is not a complete response to compromise.

### [MEDIUM-HIGH] Nilified Nonces Can Be Resurrected via Re-verification (AV5.10)

**Files:**
- `protocol/contracts/EndpointV2.sol:344-352` (_verifiable — returns true when hash != empty)
- `protocol/contracts/MessagingChannel.sol:95-105` (nilify — sets hash to NIL_PAYLOAD_HASH, not EMPTY)

**Impact:** After an OApp nilifies a nonce (setting hash to `NIL_PAYLOAD_HASH = type(uint256).max`), the `_verifiable()` check still returns true because `NIL_PAYLOAD_HASH != EMPTY_PAYLOAD_HASH`. A compromised delegate can exploit this by changing the DVN config and having a malicious DVN re-verify the nilified nonce with an attacker-controlled payload hash. `commitVerification()` then overwrites `NIL_PAYLOAD_HASH` with the attacker's hash, effectively "resurrecting" a nonce that the OApp marked as discarded.

**PoC:** `test/audit/05_AccessControl.t.sol::test_AV5_10_NilifiedNonceResurrection`

**Attack Flow:**
1. Legitimate message committed, OApp nilifies it (hash → NIL_PAYLOAD_HASH)
2. `_verifiable()` returns true (NIL_PAYLOAD_HASH != EMPTY_PAYLOAD_HASH)
3. Delegate changes config to malicious DVN + NIL_CONFIRMATIONS
4. Malicious DVN re-verifies with attacker payload hash
5. `commitVerification()` overwrites NIL_PAYLOAD_HASH with attacker hash
6. Nilification is UNDONE — nonce is now executable with attacker-controlled payload

**Mitigating factor:** Requires compromised delegate (same trust assumption as AV5.6).

---

## Medium Findings

### [MEDIUM] NIL_CONFIRMATIONS Validation Asymmetry (AV1.6)

**Files:**
- `messagelib/contracts/uln/UlnBase.sol:62` (setDefaultUlnConfigs - blocks NIL_CONFIRMATIONS)
- `messagelib/contracts/uln/UlnBase.sol:126-132` (_setUlnConfig - no confirmations validation)

**Impact:** Asymmetric validation: `setDefaultUlnConfigs()` explicitly rejects `NIL_CONFIRMATIONS` for default configs (line 62: `if (param.config.confirmations == NIL_CONFIRMATIONS) revert LZ_ULN_InvalidConfirmations()`), but `_setConfig()` for OApp-specific configs has NO such check. An OApp or delegate can set `confirmations = type(uint64).max` which resolves to 0 at read time, effectively disabling block confirmation validation.

**PoC:** `test/audit/01_QuorumBypass.t.sol::test_AV1_6_NilConfirmationsBlockedForDefaultOnly`

**Why This Matters:** The protocol explicitly considers `confirmations=0` dangerous enough to block it for default configs. The same validation should apply to OApp configs. Currently, any OApp or delegate can accidentally or maliciously set this value.

**Recommendation:** Add the same `NIL_CONFIRMATIONS` check to `_setConfig()` or `_setUlnConfig()` for OApp-specific configs.

### [MEDIUM] LzToken Balance-Based Supply Measurement Creates Shared State (AV4.3)

**Files:**
- `protocol/contracts/EndpointV2.sol:287-297` (_suppliedLzToken - uses balanceOf)
- `protocol/contracts/EndpointV2.sol:244-260` (_payToken - refund mechanism)

**Impact:** `_suppliedLzToken()` reads `IERC20(lzToken).balanceOf(address(this))` as the "supplied" amount, which includes ALL lzToken in the endpoint from ANY source. While the standard OApp flow (OAppSender._payLzToken) does atomic transfer+send in one tx (safe), any non-atomic usage is vulnerable to front-running.

**Exploitable when:** A user or script does `lzToken.transfer(endpoint, amount)` in one tx and `endpoint.send(payInLzToken=true)` in a subsequent tx. An attacker can front-run with their own `send()` call, consuming the victim's pre-deposited tokens via the refund mechanism.

**PoC:** `test/audit/04_FeeExploit.t.sol::test_AV4_3_ConcurrentSenderTokenTheft`

**Mitigating factor:** The standard OApp/OFT flow (`OAppSender._payLzToken`) is atomic. Only non-standard 2-step flows are vulnerable.

**Recommendation:** Add per-sender lzToken tracking or use `transferFrom` with approval instead of balance-based supply measurement.

### [MEDIUM] Treasury Can Drain Any ERC20 From SendLib (AV4.4/4.5)

**Files:**
- `messagelib/contracts/SendLibBaseE2.sol:77-86` (withdrawLzTokenFee - no accounting)
- `messagelib/contracts/SendLibBase.sol:43` (fees mapping - only tracks native fees)

**Impact:** `withdrawLzTokenFee()` has zero accounting validation. The `fees` mapping only tracks native fees, not lzToken fees. Treasury can call `withdrawLzTokenFee()` with any amount up to the SendLib's full ERC20 balance. Since the `_lzToken` parameter is caller-supplied, treasury can drain ANY ERC20 token from SendLib, not just the canonical lzToken.

**PoC:**
- `test/audit/04_FeeExploit.t.sol::test_AV4_4_LzTokenOverWithdrawal`
- `test/audit/04_FeeExploit.t.sol::test_AV4_5_TreasuryDrainsAnyERC20`

**Mitigating factor:** Requires treasury owner key (centralization/trust assumption).

### [MEDIUM] DVN Confirmation Overwrite Via Re-Verify (AV2.2)

**Files:**
- `messagelib/contracts/uln/ReceiveUlnBase.sol:43-46` (_verify - unconditional overwrite)
- `messagelib/contracts/uln/dvn/DVN.sol:386-392` (_shouldCheckHash - skips verify selector)

**Impact:** `_verify()` unconditionally overwrites the stored `Verification` struct. Since `verify.selector` bypasses `usedHashes` replay protection in `DVN.execute()`, a DVN can downgrade its previously submitted confirmation count by calling `verify()` again with a lower value. This can:
1. Block message delivery (DoS) by reducing confirmations below the required threshold
2. Restore delivery by re-verifying with high confirmations — enabling selective censorship
3. Enable the payload overwrite chain (AV5.6) when combined with delegate config changes

**PoC:**
- `test/audit/02_SignatureReplay.t.sol::test_AV2_2_VerifySelectorSkipsHashCheck`
- `test/audit/02_SignatureReplay.t.sol::test_AV2_2b_ConfirmationDowngradeBlocksDelivery` (demonstrates toggling)

**Mitigating factor:** Requires DVN key compromise (trust assumption).

---

## Observations (Not Vulnerabilities)

### DVN Overlap in Required/Optional Lists (AV1.4)
Same DVN in both required and optional lists passes `_assertAtLeastOneDVN` but effective quorum is 1, not 2.
**PoC:** `test/audit/01_QuorumBypass.t.sol::test_AV1_4_DVNOverlapRequiredOptional`

### LzToken Stranding on Token Address Change (AV4.6)
When `setLzToken()` changes the token address, pre-deposited old tokens are stranded in the endpoint. Users have no recovery path; only the owner can call `recoverToken()`.
**PoC:** `test/audit/04_FeeExploit.t.sol::test_AV4_6_LzTokenStrandingOnChange`

### usedHash Reset on Failed Execution (AV2.3/AV8.2)
When `DVN.execute()` fails, `usedHashes[hash]` is reset to false, allowing the same instruction to be retried. This is by design for operational recovery but creates a TOCTOU window.

### DVN Arbitrary Call via execute() (AV8.1)
A compromised DVN signer quorum can approve arbitrary ERC20 calls via `execute()`, draining tokens held by the DVN contract. Requires signer key compromise.
**PoC:** `test/audit/08_LzTokenDrain.t.sol::test_AV8_1_ArbitraryCallTarget`

### EndpointV2Alt Native Fee Race Condition
`EndpointV2Alt._suppliedNative()` uses `IERC20(nativeErc20).balanceOf(address(this))` instead of `msg.value`. This means the same shared-balance race condition that affects lzToken fees in EndpointV2 also affects native fees on Alt chains (non-ETH chains like some L2s). More impactful than AV4.3 since native fees are required for ALL messages, not just lzToken-paying ones. Same mitigation: standard OApp flow is atomic.
**File:** `protocol/contracts/EndpointV2Alt.sol:39-41`

### Delegate Can Block Outbound Messages via Library Swap (AV5.8)
Compromised delegate can call `setSendLibrary(oapp, eid, blockedLibrary)` to route all outbound messages through the blocked library, which reverts on both `send()` and `quote()`. Recoverable if the OApp owner can call `setSendLibrary()` directly, but causes operational disruption.
**PoC:** `test/audit/05_AccessControl.t.sol::test_AV5_8_DelegateSendLibSwap_BlocksOutbound`

### Compose Front-Running (OApp-Level, Not Protocol)
`endpoint.lzCompose()` has no access control beyond the compose hash check. Anyone who knows the compose message (emitted in `ComposeSent` event) can call `lzCompose()` before the executor, delivering with `value=0` and forged `_extraData`. The protocol explicitly documents "the composer MUST assert the sender" (MessagingComposer.sol:17). This is an OApp-developer trap, not a protocol bug — the security burden is on each compose receiver to validate `msg.sender == endpoint` and check `msg.value`.

### Treasury Fee System Is DoS-Resistant
`_payTreasury()` uses `safeCall` with gas limit + return data cap. If treasury reverts or returns garbage, fee = 0 and message proceeds. Native fees are capped at `max(totalNativeFee, treasuryNativeFeeCap)`. lzToken fees are uncapped (documented design choice). No protocol-level vulnerability.

### Worker Fee Accounting Is Correct
`fees[worker] += amount` properly tracks native fees per worker. `_debitFee(amount)` checks `fees[msg.sender]` before withdrawal. `withdrawLzTokenFee()` lacks accounting (see AV4.4/4.5 above), but native fee path is solid.

### Config Resolution Is Defense-in-Depth
All five edge cases tested (no default config, DVN array mismatch, NIL_DVN_COUNT, non-existent EID, partial override). `_assertAtLeastOneDVN` catch-all prevents zero-DVN configs. `_assertSupportedEid` blocks configs for non-existent EIDs. Field-group-atomic resolution prevents cross-source field mixing.

### Reentrancy Protection Is Solid (AV7)
CEI pattern is consistently applied. `lzReceive` clears payload before external call. `sendContext` modifier prevents re-entry to `send()`. ReentrantReceiver test confirms protection.

### Compose Queue Is Safe From Permanent Consumption Griefing (AV7.4)
`MessagingComposer.lzCompose()` writes `RECEIVED_MESSAGE_HASH` (line 56) BEFORE the external call to the OApp handler (line 57). However, since `lzCompose()` has NO try/catch, a handler revert propagates and reverts the state write too. The Executor's `compose302()` uses try/catch around `endpoint.lzCompose()`, but since the state write is INSIDE the called frame, it still reverts on failure. Compose entries are NOT permanently consumed on handler failure.

### GUID Uniqueness Is Guaranteed
`GUID.generate()` uses `keccak256(abi.encodePacked(nonce, srcEid, sender32, dstEid, receiver))` with all fixed-size fields. `sender` is padded to `bytes32` via `AddressCast.toBytes32()`, eliminating `abi.encodePacked` boundary ambiguity. Nonce monotonicity per `(sender, dstEid, receiver)` path ensures no GUID collision.

### Compose Queue Has No Ordering Enforcement
Compose indices can be executed in any order. Index 5 can execute before index 0 with no revert. OApps that implement stateful compose handlers assuming sequential execution bear the ordering risk. This is a documented design choice.

### Nonce System Is Sound (AV3.4-3.7)
- `skip()` preserves already-verified nonces for later execution (AV3.4)
- `burn()` creates permanent tombstone: nonce(N) <= lazyInboundNonce AND hash == EMPTY means `_verifiable()` returns false forever (AV3.5)
- `nilify()` allows re-verification as a recovery mechanism because NIL_PAYLOAD_HASH != EMPTY_PAYLOAD_HASH (AV3.6)
- Execution requires contiguous nonces: gaps block delivery until filled via verification or nilification (AV3.7)
- No double-execution vulnerability exists: `_clearPayload()` deletes hash before OApp receives control

---

## Bounty Submission Strategy

### Submitted
1. **AV3+AV6 (CRITICAL):** Payload overwrite via grace period + reverification

### Ready to Submit
2. **AV5+AV1 (HIGH):** Delegate config retroactivity + payload overwrite without grace period
   - Different root cause than AV3+AV6 (config manipulation vs. library upgrade)
   - Demonstrates that `_inbound()` overwrite is exploitable through MULTIPLE paths
   - Strong case for fixing `_inbound()` rather than just the grace period path
3. **AV5.7 (HIGH):** Delegate nilify-skip-burn permanent message destruction
   - No external DVN needed -- uses only built-in protocol operations
   - 3-step chain: nilify -> skip -> burn permanently kills a verified nonce
   - Strengthens AV5 submission by showing delegate power extends beyond config manipulation

### Consider Submitting
4. **AV5.10 (MEDIUM-HIGH):** Nilified nonce resurrection via re-verification
5. **AV1.6 (MEDIUM):** NIL_CONFIRMATIONS validation asymmetry
6. **AV4.3 (MEDIUM):** lzToken balance race condition

### Supplementary Evidence (bundle with AV5 submission)
- **AV5.9 (MEDIUM):** Config persistence after delegate revocation — strengthens AV5 case
- **AV2.2b:** DVN confirmation downgrade as DoS vector — shows verify replay enables selective censorship

---

## Test Suite Summary

| File | Tests | Status |
|------|-------|--------|
| 01_QuorumBypass.t.sol | 7 | ALL PASS |
| 02_SignatureReplay.t.sol | 5 | ALL PASS |
| 03_NonceManipulation.t.sol | 7 | ALL PASS |
| 04_FeeExploit.t.sol | 6 | ALL PASS |
| 05_AccessControl.t.sol | 11 | ALL PASS |
| 06_GracePeriod.t.sol | 4 | ALL PASS |
| 07_Reentrancy.t.sol | 3 | ALL PASS |
| 08_LzTokenDrain.t.sol | 3 | ALL PASS |
| 09_CriticalPoC.t.sol | 3 | ALL PASS |
| **TOTAL** | **49** | **ALL PASS** |
