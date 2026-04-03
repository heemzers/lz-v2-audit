# Immunefi Bug Report: Delegate Config Retroactivity - Payload Overwrite

## Bug Description

A high-severity vulnerability exists in the interaction between `ReceiveUln302.commitVerification()`, `UlnBase` config resolution, and `MessagingChannel._inbound()`. The root cause is that ULN security config (required DVNs, required confirmations) is read at `commitVerification()` time rather than at DVN verify time. Because no snapshot of the config is captured when DVNs submit their attestations, a compromised delegate can retroactively weaken security parameters between the DVN verification step and the commit step — or after a legitimate message has already been committed — to overwrite the stored payload hash with an attacker-controlled value.

A compromised OApp delegate has the power to call `setConfig()` on the receive ULN at any time. By swapping the OApp's required DVN set to a malicious DVN and setting `confirmations` to `NIL_CONFIRMATIONS` (`type(uint64).max`, which resolves to 0 in `UlnBase._getUlnConfig()`), the delegate creates a configuration that allows a single attacker-controlled DVN to immediately satisfy `_checkVerifiable()`. The malicious DVN then calls `verify()` with a different payload hash targeting the same nonce. A subsequent call to `commitVerification()` reads the live (weakened) config, passes all security checks, calls `endpoint.verify()`, and `_inbound()` unconditionally overwrites the legitimate inbound payload hash with the attacker-controlled one.

Once the legitimate payload hash is overwritten, the original cross-chain message can never execute: `lzReceive()` reverts on hash mismatch, and all recovery functions (`clear`, `nilify`, `burn`) also fail because they operate on the stored hash rather than restoring the original. Any in-flight value transfer — OFT token bridges, cross-chain swaps, NFT mints — is permanently lost. This attack requires no library upgrade, no grace period, and no admin-level protocol access beyond a compromised OApp delegate.

## Impact

**Permanent loss of user funds.** Any cross-chain message that has been verified by legitimate DVNs but not yet executed via `lzReceive()` can have its stored payload hash overwritten by an attacker-controlled hash, permanently blocking execution. The economic impact scales with the value of in-flight cross-chain transfers. For protocols with large message queues (batch transfers, scheduled settlements, bridge withdrawals), a single delegate compromise can block many messages simultaneously. Once overwritten, there is no on-chain recovery path: the nonce is consumed, the original payload hash is gone, and the corresponding source-chain funds (already burned or locked during `send()`) can never be credited on the destination chain.

The affected parties are end users of any OApp (OFT, bridge, cross-chain governance) whose delegate key is compromised. The attacker needs: (1) control of the OApp's delegate address, and (2) ability to deploy or control a single DVN contract. The delegate key is often a hot wallet or multisig with weaker security guarantees than the OApp owner itself.

## Severity: HIGH

This finding is rated HIGH for the following reasons:

- **Direct fund loss**: The vulnerability results in permanent, irreversible loss of in-flight cross-chain funds, the highest-impact class of DeFi vulnerability.
- **No protocol-level prerequisite**: Unlike the previously submitted AV3+AV6 finding, this attack does not require a library upgrade or grace period. It works against any OApp at any time as long as the delegate is compromised.
- **Low attacker cost**: The attacker only needs to control the OApp's delegate (a common operational key) and deploy one DVN contract. No DVN quorum on a production library is required.
- **No on-chain recovery**: Once `_inbound()` overwrites the payload hash, every recovery path fails. There is no administrative function that can restore the original hash.
- **Broad exposure**: Every OApp that sets a delegate — which is recommended operational practice for many protocol patterns — is exposed to this attack surface.

The finding does not reach CRITICAL because it requires compromise of the OApp's own delegate key (an insider/key-management failure) rather than an external attacker with no privileged access.

## Root Cause

The fundamental issue is that `ReceiveUln302.commitVerification()` reads the live ULN config from storage at the moment of the commit call, rather than using the config that was active when DVNs submitted their individual attestations. There is no per-nonce snapshot of the security parameters in effect at verify time.

**Config is read at commit time, not at verify time** (`ReceiveUln302.sol:48-61`):

```solidity
function commitVerification(bytes calldata _packetHeader, bytes32 _payloadHash) external {
    _assertReceiveLibrary(endpoint, _packetHeader.dstEid());
    // reads LIVE config — not a snapshot from verify time
    UlnConfig memory config = getUlnConfig(_packetHeader.receiver(), _packetHeader.srcEid());
    _checkVerifiable(config, keccak256(_packetHeader), _payloadHash, _packetHeader.srcEid());
    ILayerZeroEndpointV2(endpoint).verify(
        Origin(...), receiver, _payloadHash
    );
}
```

**NIL_CONFIRMATIONS always resolves to 0 for OApp configs** (`UlnBase.sol:79-85`):

```solidity
uint64 confirmations = customConfig.confirmations;
if (confirmations == DEFAULT) {
    rtnConfig.confirmations = defaultConfig.confirmations;
} else if (confirmations != NIL_CONFIRMATIONS) {
    rtnConfig.confirmations = confirmations;
} // else do nothing, rtnConfig.confirmation is 0
```

When an OApp sets `confirmations = type(uint64).max` (NIL_CONFIRMATIONS), neither branch executes — `rtnConfig.confirmations` remains at its default memory value of `0`, **regardless of what the default config specifies**. Even if the default config has `confirmations = 20`, the OApp override to NIL_CONFIRMATIONS always produces 0. This unconditionally disables the block confirmation requirement.

**`_inbound()` performs an unconditional overwrite** (`MessagingChannel.sol:37-46`):

```solidity
function _inbound(..., bytes32 _payloadHash) internal {
    if (_payloadHash == EMPTY_PAYLOAD_HASH) revert Errors.LZ_InvalidPayloadHash();
    // no check for existing non-empty value
    inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash;
}
```

**`_verifiable()` permits re-verification of already-committed nonces** (`EndpointV2.sol:344-352`): a nonce with an existing non-empty `inboundPayloadHash` is treated as verifiable, not as already-final.

### File References

- `protocol/contracts/EndpointV2.sol:355-357` — `_assertAuthorized()` gives delegate full power over OApp config, including `setConfig()`
- `messagelib/contracts/uln/uln302/ReceiveUln302.sol:48-61` — `commitVerification()` reads live config at commit time with no snapshot
- `messagelib/contracts/uln/UlnBase.sol:79-85` — `NIL_CONFIRMATIONS` (`type(uint64).max`) resolves to 0 for OApp configs when no stronger default is set
- `messagelib/contracts/uln/ReceiveUlnBase.sol:43-46` — `_verify()` stores DVN attestation with no config snapshot
- `protocol/contracts/MessagingChannel.sol:37-46` — `_inbound()` blind overwrite of `inboundPayloadHash`

## Attack Scenario

**Prerequisites:**
- A deployed OApp (e.g., an OFT bridge) with a delegate set to address `D`
- A legitimate cross-chain message in flight: verified by the OApp's legitimate DVN set but not yet executed via `lzReceive()`
- Address `D` is compromised (stolen private key, malicious multisig signer, social engineering)

**Step 1:** OApp deploys with a strong security config: 3 required DVNs, 20 confirmations. Delegate `D` is set via `EndpointV2.setDelegate(D)`.

**Step 2:** A legitimate high-value message (e.g., a 100 ETH OFT transfer) is verified by all 3 DVNs with 20+ block confirmations. `commitVerification(header, legitimatePayloadHash)` is called and succeeds. `inboundPayloadHash[oapp][srcEid][sender][nonce] = legitimatePayloadHash` is set. The message is waiting for the recipient to call `lzReceive()`.

**Step 3:** Attacker (controlling `D`) deploys `maliciousDVN`, a DVN contract they fully control. This requires no special permissions — DVNs are permissionlessly deployed.

**Step 4:** Attacker calls `EndpointV2.setConfig(oapp, receiveUln, [{configType: CONFIG_TYPE_ULN, config: abi.encode(weakConfig)}])` via delegate `D`, where `weakConfig` specifies:
- `requiredDVNs = [maliciousDVN]`
- `confirmations = type(uint64).max` (NIL_CONFIRMATIONS, resolves to 0)
- `requiredDVNCount = 1`

The OApp's ULN config is now effectively: 1 DVN (attacker-controlled), 0 confirmations required.

**Step 5:** Attacker calls `maliciousDVN.verify(header, maliciousPayloadHash, 0)`, submitting a verification for the same packet header but a different payload hash. `maliciousPayloadHash` decodes to a payload that, for example, sends the 100 ETH to the attacker's address on the destination chain.

**Step 6:** Anyone calls `commitVerification(header, maliciousPayloadHash)`:
- `getUlnConfig(oapp, srcEid)` returns the weakened config (live read)
- `NIL_CONFIRMATIONS` resolves to 0 confirmations required
- `_checkVerifiable` passes: `maliciousDVN` has submitted && `0 >= 0`
- `endpoint.verify()` is called
- `_verifiable()` returns `true` because `inboundPayloadHash != EMPTY_PAYLOAD_HASH`
- `_inbound()` overwrites `legitimatePayloadHash` with `maliciousPayloadHash`

**Step 7:** `inboundPayloadHash[oapp][srcEid][sender][nonce]` now holds `maliciousPayloadHash`.

**Step 8 (fund loss):** The recipient calls `lzReceive(origin, legitimatePayload)`. The endpoint checks `keccak256(legitimatePayload) != maliciousPayloadHash` and reverts with `LZ_PayloadHashNotFound`. All recovery paths fail:
- `lzReceive(legitimatePayload)` — reverts (hash mismatch)
- `clear(oapp, origin, bytes32(0), legitimatePayload)` — reverts (hash mismatch)
- `nilify(oapp, origin, legitimatePayloadHash)` — reverts (stored hash is `maliciousPayloadHash`, not `legitimatePayloadHash`)
- `burn(oapp, origin, legitimatePayloadHash)` — reverts (same reason)
- `skip()` — only advances `inboundNonce`; the already-verified nonce's hash is permanently stuck

The 100 ETH burned on the source chain during `send()` can never be credited. Funds are permanently lost.

## Proof of Concept

Test file: `packages/layerzero-v2/evm/messagelib/test/audit/05_AccessControl.t.sol`

**Test 1: `test_AV5_5_ConfigRetroactivity_DelegateWeakensBeforeCommit`**

Demonstrates the retroactivity property: all 3 DVNs verify under a 3-of-3 / 20-confirmation config. The delegate weakens the config to 1-of-3 / 0-confirmation before `commitVerification()` is called. `commitVerification()` succeeds under the weakened config, proving that the original security intent of 3 DVNs and 20 confirmations is entirely bypassed retroactively.

**Test 2: `test_AV5_6_PayloadOverwriteViaConfigChangeAndReverify`**

Demonstrates the full payload overwrite attack chain:
1. Legitimate message committed under default 1-DVN config
2. Delegate swaps DVN set to `maliciousDVN` with `NIL_CONFIRMATIONS`
3. `maliciousDVN` verifies with `keccak256("malicious_payload")`
4. Re-commit via `commitVerification()` overwrites the stored `inboundPayloadHash`
5. `assertEq(storedAfter, maliciousPayloadHash)` and `assertTrue(storedAfter != legitimatePayloadHash)` both pass

**Test 3: `test_AV5_7_DelegateNilifySkipBurn_PermanentDestruction`** (supplementary)

Demonstrates an alternative destruction path using only built-in protocol operations (no external DVN deployment). The delegate chains nilify → skip → burn to permanently destroy a verified message. This test is supplementary — it demonstrates the breadth of delegate power and supports the recommendation for timelocked config/operation changes rather than being a standalone finding.

**Test 4: `test_AV5_9_ConfigPersistsAfterDelegateRevocation`** (supplementary)

Demonstrates that ULN config changes persist after delegate revocation. The OApp owner revokes the compromised delegate, but the weakened config (malicious DVN + 0 confirmations) remains active. A malicious DVN can still commit fraudulent messages AFTER the delegate is revoked. The OApp owner must manually restore the config — delegate revocation alone is insufficient. The test also confirms the OApp owner CAN manually restore configs, so this is an operational awareness gap.

**Test 5: `test_AV5_10_NilifiedNonceResurrection`** (supplementary)

Demonstrates that a nilified nonce can be "resurrected" via re-verification. After `nilify()` sets the hash to `NIL_PAYLOAD_HASH` (`type(uint256).max`), the `_verifiable()` check still returns true because `NIL_PAYLOAD_HASH != EMPTY_PAYLOAD_HASH` (bytes32(0)). A compromised delegate can change the DVN config and have a malicious DVN re-verify the nilified nonce with an attacker-controlled payload hash, overwriting the nilification. This demonstrates that `nilify()` does not provide permanent discarding — only `nilify + skip + burn` (Test 3) is truly permanent.

Run the tests:

```bash
forge test --match-path test/audit/05_AccessControl.t.sol -vvv
```

All 10 tests pass, confirming the vulnerabilities exist in the current codebase.

## Distinction from Previously Submitted Finding (AV3+AV6)

This is a DIFFERENT vulnerability from the previously submitted "Payload Overwrite via Grace Period + Reverification" finding. Both share the same underlying `_inbound()` unconditional overwrite as the final write primitive, but the attack entry points and prerequisites are entirely different.

| Aspect | AV3+AV6 (Previously Submitted) | AV5+AV1 (This Report) |
|---|---|---|
| Trigger | Library upgrade with non-zero grace period | No library upgrade needed |
| Attack vector | DVN quorum on deprecated library | Config manipulation via delegate |
| Root cause | `isValidReceiveLibrary` accepts both old and new library during grace period | Config read at commit time, not verify time — no snapshot |
| Prerequisite | Admin performs library upgrade; attacker controls deprecated library's DVN quorum | Compromised OApp delegate + deploy one malicious DVN |
| DVN requirement | Must control quorum of the OLD (production) library's DVNs | Deploy a new malicious DVN with no special status |
| Grace period | Required (attack window = grace period) | Not required |
| Attack window | Bounded by grace period duration | Unbounded — config change is instant |
| Message state required | Message verified but not executed | Message can be before or after first commit |

The AV3+AV6 finding is an external attacker path requiring structural conditions (an in-progress library migration). This finding is an insider/key-compromise path that is always available to a compromised delegate, regardless of protocol upgrade state.

## Recommended Fix

**Option A (strongest — address the write primitive):** `_inbound()` in `MessagingChannel.sol` should reject overwriting an existing non-empty payload hash when the caller is the same receive library. The unconditional overwrite is the shared root of both this finding and AV3+AV6. Allowing same-library re-commits on already-committed nonces serves no legitimate use case.

```solidity
function _inbound(..., bytes32 _payloadHash) internal {
    if (_payloadHash == EMPTY_PAYLOAD_HASH) revert Errors.LZ_InvalidPayloadHash();
    bytes32 existing = inboundPayloadHash[_receiver][_srcEid][_sender][_nonce];
    if (existing != EMPTY_PAYLOAD_HASH && existing != _payloadHash) {
        revert Errors.LZ_PayloadAlreadyVerified();
    }
    inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash;
}
```

**Option B (defense-in-depth — add timelock to DVN/confirmation config changes):** Add a mandatory delay (e.g., 24–48 hours) to ULN config changes that affect required DVN sets or confirmation counts. This prevents a compromised delegate from instantly weakening security to attack in-flight messages, converting a single-transaction attack into one that requires sustained access across a time window.

**Option C (snapshot approach — eliminate retroactivity):** Capture a snapshot of the effective ULN config at the time each DVN calls `verify()` and store it alongside the attestation. `commitVerification()` should verify that the current config is at least as strong as the config that was active when the weakest-submitted DVN attested. Any weakening of the config after DVN attestation should invalidate pending verifications.

**Option D (close the NIL_CONFIRMATIONS gap for OApp configs):** `NIL_CONFIRMATIONS` is already blocked for default configs at `UlnBase.sol:62`. The same validation should apply when OApp-level configs are set: reject a DVN-set change or confirmation override that would resolve to 0 effective confirmations unless the default itself specifies 0.

Option A is strongly recommended as it closes both this attack vector and AV3+AV6 at the source, and also prevents nilified nonce resurrection (Test 5). Options B–D are complementary mitigations that address contributing factors.
