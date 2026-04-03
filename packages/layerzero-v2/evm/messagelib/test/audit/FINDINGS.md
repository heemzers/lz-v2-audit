# LayerZero-v2 Bug Bounty Findings

**Program:** Immunefi LayerZero-v2 ($250K-$15M for critical)
**Scope:** Theft or permanent locking of user funds
**Started:** 2026-04-02
**Updated:** 2026-04-03

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

**PoC:** `test/audit/05_AccessControl.t.sol::test_AV5_6_PayloadOverwriteViaConfigChangeAndReverify`

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
2. Enable the payload overwrite chain (AV5.6) when combined with delegate config changes

**PoC:** `test/audit/02_SignatureReplay.t.sol::test_AV2_2_VerifySelectorSkipsHashCheck`

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

### Reentrancy Protection Is Solid (AV7)
CEI pattern is consistently applied. `lzReceive` clears payload before external call. `sendContext` modifier prevents re-entry to `send()`. ReentrantReceiver test confirms protection.

---

## Bounty Submission Strategy

### Submitted
1. **AV3+AV6 (CRITICAL):** Payload overwrite via grace period + reverification

### Ready to Submit
2. **AV5+AV1 (HIGH):** Delegate config retroactivity + payload overwrite without grace period
   - Different root cause than AV3+AV6 (config manipulation vs. library upgrade)
   - Demonstrates that `_inbound()` overwrite is exploitable through MULTIPLE paths
   - Strong case for fixing `_inbound()` rather than just the grace period path

### Consider Submitting
3. **AV1.6 (MEDIUM):** NIL_CONFIRMATIONS validation asymmetry
4. **AV4.3 (MEDIUM):** lzToken balance race condition

---

## Test Suite Summary

| File | Tests | Status |
|------|-------|--------|
| 01_QuorumBypass.t.sol | 7 | ALL PASS |
| 02_SignatureReplay.t.sol | 4 | ALL PASS |
| 03_NonceManipulation.t.sol | 3 | ALL PASS |
| 04_FeeExploit.t.sol | 6 | ALL PASS |
| 05_AccessControl.t.sol | 6 | ALL PASS |
| 06_GracePeriod.t.sol | 4 | ALL PASS |
| 07_Reentrancy.t.sol | 3 | ALL PASS |
| 08_LzTokenDrain.t.sol | 3 | ALL PASS |
| 09_CriticalPoC.t.sol | 3 | ALL PASS |
| **TOTAL** | **39** | **ALL PASS** |
