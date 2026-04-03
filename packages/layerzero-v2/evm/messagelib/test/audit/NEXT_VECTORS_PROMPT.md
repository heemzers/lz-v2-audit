# LayerZero-v2 Bug Bounty: Remaining 6 Attack Vectors

**Objective:** Find the next critical/high vulnerability in LayerZero-v2 for the Immunefi bounty ($100K-$15M for critical, up to $250K for high). We already confirmed one critical finding (AV3+AV6: payload overwrite via grace period + reverification). Now hunt for the next one.

**MAXIMIZE EARNINGS: Focus effort on vectors most likely to yield critical/high severity findings with provable fund loss. Skip vectors that are clearly "by design" trust assumptions.**

**Repo:** `/Users/fahim/projects/autocode-tests/LayerZero-v2`
**Test base:** `packages/layerzero-v2/evm/messagelib/test/audit/`
**Run tests:** `~/.foundry/bin/forge test --match-path test/audit/ -vvv`
**Existing infrastructure:** `AuditBase.t.sol` provides full 2-chain V2 stack with DVN control.

---

## PRIORITY 1: AV4 - Fee Exploitation (CRITICAL potential, $100K-$15M)

### Why This Is #1

Deep code analysis revealed a **critical accounting gap**: `SendLibBaseE2.withdrawLzTokenFee()` performs NO debit tracking for lzToken fees. The `fees` mapping only tracks native fees. Treasury can call `withdrawLzTokenFee()` to extract ANY amount of lzTokens from the SendLib with zero validation against what was actually paid in. If this is exploitable without treasury owner compromise, it's a critical finding.

### Exact Code to Exploit

**File 1: `protocol/contracts/EndpointV2.sol` — `_suppliedLzToken()` (lines 287-297)**
```solidity
function _suppliedLzToken(bool _payInLzToken) internal view returns (uint256 supplied) {
    if (_payInLzToken) {
        supplied = IERC20(lzToken).balanceOf(address(this)); // <-- USES BALANCE, NOT PER-SENDER TRACKING
        if (supplied == 0) revert Errors.LZ_ZeroLzTokenFee();
    }
}
```
- Uses `balanceOf(address(this))` — any tokens sitting in the endpoint are "supplied"
- No per-sender tracking
- Race condition: if Alice and Bob both transfer lzToken to endpoint in the same block, Alice's tx could consume Bob's tokens

**File 2: `messagelib/contracts/SendLibBase.sol` — `withdrawFee()` vs `withdrawLzTokenFee()`**
```solidity
// Native fees: PROPERLY TRACKED
function _debitFee(uint256 _amount) internal {
    uint256 fee = fees[msg.sender]; // <-- checks against tracked balance
    if (_amount > fee) revert LZ_MessageLib_InvalidAmount(_amount, fee);
    unchecked { fees[msg.sender] = fee - _amount; }
}

// LzToken fees: NO TRACKING AT ALL
function withdrawLzTokenFee(address _lzToken, address _to, uint256 _amount) external {
    if (msg.sender != treasury) revert LZ_MessageLib_NotTreasury();
    // NO CHECK against accumulated fees
    // NO debit from any mapping
    Transfer.token(_lzToken, _to, _amount); // <-- just transfers whatever you ask for
}
```

**File 3: `messagelib/contracts/Treasury.sol` — `withdrawLzToken()` (lines 49-55)**
```solidity
function withdrawLzToken(address _messageLib, address _lzToken, address _to, uint256 _amount) external onlyOwner {
    ISendLib(_messageLib).withdrawLzTokenFee(_lzToken, _to, _amount);
}
```

### Attack Hypotheses to Test

1. **LzToken over-withdrawal**: Can treasury withdraw more lzTokens than were paid in fees? The `withdrawLzTokenFee()` only checks `msg.sender == treasury` and that `_lzToken != nativeToken`. No balance validation. If SendLib has accumulated lzTokens from user fees, treasury can drain ALL of them — potentially including tokens that rightfully belong to other actors.

2. **Race condition between concurrent senders**: Two users both transfer lzToken to EndpointV2 and call `send(payInLzToken=true)` in the same block. First sender gets `balanceOf = their_tokens + other_tokens`. The `_payToken()` function at EndpointV2:244-260 transfers `_required` to SendLib and refunds `_supplied - _required` to `_refundAddress`. Can the first sender steal the second sender's tokens via the refund mechanism?

3. **LzToken change race**: Owner calls `setLzToken(newToken)` between a user's `approve()` and `send()`. The `_suppliedLzToken()` checks `balanceOf` of the NEW token. Old tokens left in endpoint are orphaned. Can an attacker exploit the token change to redirect fees?

4. **Fee accumulation overflow**: The `fees[worker] += amount` uses Solidity 0.8.x checked arithmetic, but if a worker accumulates massive fees across many transactions, could the fee accounting become inconsistent?

### Key Questions to Answer

- Is `withdrawLzTokenFee()` the only way lzTokens leave SendLib? Or does SendLib forward them elsewhere?
- Does the treasury owner have independent motivations to over-withdraw? (If treasury == LayerZero team, this is a trust assumption, not a vulnerability)
- Can the `_suppliedLzToken()` race condition cause **permanent** fund loss, or just temporary griefing?
- What happens to lzTokens accumulated in SendLib when `setLzToken()` changes the token address?

### Files to Read

- `protocol/contracts/EndpointV2.sol` — `send()` (line 86-143), `_suppliedLzToken()` (287-297), `_payToken()` (244-260), `setLzToken()` (224-227)
- `messagelib/contracts/SendLibBase.sol` — `fees` mapping, `_debitFee()` (228-234), `_payTreasury()` (120-139), `_payWorkers()`
- `messagelib/contracts/SendLibBaseE2.sol` — `withdrawFee()` (66-72), `withdrawLzTokenFee()` (77-86), `send()` override
- `messagelib/contracts/Treasury.sol` — full file, `payFee()`, `withdrawLzToken()`, `withdrawNativeFee()`
- `protocol/contracts/libs/Transfer.sol` — `token()`, `native()`, `nativeOrToken()` implementations
- Existing test: `test/audit/04_FeeExploit.t.sol`

### PoC Template

```solidity
// In test/audit/04_FeeExploit.t.sol — add new tests

/// @dev Test: Can treasury over-withdraw lzTokens?
function test_AV4_3_LzTokenOverWithdrawal() public {
    // 1. Deploy an lzToken mock, set it on endpoint
    // 2. User sends message with payInLzToken=true (transfers lzToken to endpoint)
    // 3. Endpoint forwards lzTokenFee to SendLib
    // 4. Treasury calls withdrawLzTokenFee with MORE than what was paid
    // 5. Assert: does the call succeed? Does SendLib lose tokens?
}

/// @dev Test: Race condition between concurrent senders
function test_AV4_4_ConcurrentSenderTokenTheft() public {
    // 1. Alice transfers 10 lzToken to endpoint
    // 2. Bob transfers 5 lzToken to endpoint (same block)
    // 3. Alice calls send(payInLzToken=true) — _suppliedLzToken returns 15
    // 4. Alice's fee is 8 lzToken, refund = 15 - 8 = 7 to Alice
    // 5. Bob calls send(payInLzToken=true) — _suppliedLzToken returns 0 (all consumed)
    // 6. Assert: Bob lost 5 tokens to Alice's refund
}
```

---

## PRIORITY 2: AV1 - DVN Quorum Bypass (HIGH potential, up to $250K)

### Why This Is #2

`NIL_CONFIRMATIONS` (uint64.max) resolves to `confirmations = 0` in the final config. When confirmations = 0, the `_verified()` check becomes `confirmations >= 0` which is **always true** for any uint64. This effectively disables block confirmation validation. The key question: is there a path where this happens WITHOUT the OApp explicitly choosing it?

### Exact Code to Exploit

**File 1: `messagelib/contracts/uln/UlnBase.sol` — Config resolution (lines 74-118)**
```solidity
// NIL_CONFIRMATIONS resolution (lines 82-85):
if (customConfig.confirmations == DEFAULT) {
    rtnConfig.confirmations = defaultConfig.confirmations;
} else if (customConfig.confirmations != NIL_CONFIRMATIONS) {
    rtnConfig.confirmations = customConfig.confirmations;
}
// ELSE: rtnConfig.confirmations stays at DEFAULT value (0) ← THIS IS THE BUG PATH
```

**File 2: `messagelib/contracts/uln/ReceiveUlnBase.sol` — `_verified()` (lines 48-57)**
```solidity
function _verified(address _dvn, bytes32 _headerHash, bytes32 _payloadHash, uint64 _requiredConfirmation)
    internal view returns (bool) {
    Verification memory verification = hashLookup[_headerHash][_payloadHash][_dvn];
    verified = verification.submitted && verification.confirmations >= _requiredConfirmation;
    // When _requiredConfirmation = 0: ANY submitted verification passes (0 >= 0 = true)
}
```

**File 3: `messagelib/contracts/uln/UlnBase.sol` — Guard (line 117 and 146-148)**
```solidity
function _assertAtLeastOneDVN(UlnConfig memory _config) private pure {
    if (_config.requiredDVNCount == 0 && _config.optionalDVNThreshold == 0)
        revert LZ_ULN_AtLeastOneDVN();
}
// NOTE: This does NOT check confirmations. Zero confirmations passes this guard.
```

### Attack Hypotheses to Test

1. **Delegate sets NIL_CONFIRMATIONS on behalf of OApp**: An OApp's delegate (who has full config power via AV5) calls `setConfig()` to set `confirmations = NIL_CONFIRMATIONS`. The config resolves to 0 confirmations. Now any DVN verification with even 0 confirmations passes. Can a compromised delegate weaponize this to accept unfinalized messages?

2. **Default config resolution gap**: If the DEFAULT config has `confirmations = X` but an OApp overrides with `NIL_CONFIRMATIONS`, the final config has confirmations = 0. Can this be combined with a reorg attack on source chain where a message was included in a block that gets reverted?

3. **NIL_DVN_COUNT for required + low optional threshold**: An OApp sets `requiredDVNCount = NIL_DVN_COUNT` (override to 0) + `optionalDVNCount = 1, optionalDVNThreshold = 1`. This passes `_assertAtLeastOneDVN` (threshold > 0). Now only 1 optional DVN is needed, AND if confirmations = 0 (via NIL_CONFIRMATIONS), the quorum is trivially satisfied. Can this be chained to verify fraudulent messages?

4. **Config frontrunning**: Can an attacker frontrun a `setConfig` transaction to set malicious config before a legitimate config update lands?

### Key Questions to Answer

- Is `confirmations = 0` ever legitimate? What does it mean operationally? (Instant finality assumption?)
- Can an OApp's config be set by anyone other than the OApp itself or its delegate?
- Does `setConfig()` in the ULN have any additional guards beyond `_assertAtLeastOneDVN`?
- If confirmations = 0, can a DVN submit a verification with `confirmations = 0` (i.e., no block finality proof)?

### Files to Read

- `messagelib/contracts/uln/UlnBase.sol` — full file (config resolution, sentinels, guards)
- `messagelib/contracts/uln/ReceiveUlnBase.sol` — `_checkVerifiable()` (90-124), `_verified()` (48-57)
- `messagelib/contracts/uln/uln302/ReceiveUln302.sol` — `setConfig()` and `getConfig()` implementations
- Existing test: `test/audit/01_QuorumBypass.t.sol`

---

## PRIORITY 3: AV2 - MultiSig Signature Replay (MEDIUM potential, up to $25K)

### Why This Is #3

Cross-DVN replay with shared `vid` is confirmed possible. The `vid` field has no uniqueness enforcement at the contract level. Additionally, the 3 verify selectors skip `usedHashes` replay protection, meaning a DVN operator can downgrade their own block confirmations by re-calling verify with lower values.

### Exact Code to Exploit

**DVN.sol — Hash construction (line 376):**
```solidity
keccak256(abi.encodePacked(_vid, _target, _expiration, _callData))
// vid is uint32, set at construction, NO uniqueness check
```

**DVN.sol — Replay protection skip (lines 386-392):**
```solidity
function _shouldCheckHash(bytes4 _functionSig) internal pure returns (bool) {
    return _functionSig != IReceiveUlnE2.verify.selector &&
           _functionSig != ReadLib1002.verify.selector &&
           _functionSig != ILayerZeroUltraLightNodeV2.updateHash.selector;
}
```

**DVN.sol — Hash reset on failure (lines 210-218):**
```solidity
(bool success, bytes memory rtnData) = param.target.call(param.callData);
if (!success) {
    if (shouldCheckHash) { usedHashes[hash] = false; } // RESET
}
```

### Attack Hypotheses to Test

1. **Cross-DVN replay with shared vid**: Deploy two DVNs with the same vid. Sign an instruction targeting an external contract (e.g., ReceiveUln302). The same signature works on both DVNs. Can this be used to double-verify a message or bypass quorum requirements?

2. **Confirmation downgrade via verify replay**: Since verify.selector bypasses `usedHashes`, a DVN operator can call `execute()` with verify(header, payloadHash, LOW_CONFIRMATIONS) after already calling verify(header, payloadHash, HIGH_CONFIRMATIONS). Does `_verify()` in ReceiveUlnBase overwrite the stored confirmation count?

3. **TOCTOU hash reset exploitation**: Sign an instruction to a target that initially reverts. Hash resets. Target contract is upgraded/redeployed. Replay the instruction — now it succeeds. The same signature executes twice in different contexts.

### Files to Read

- `messagelib/contracts/uln/dvn/DVN.sol` — `execute()`, `hashCallData()`, `_shouldCheckHash()`
- `messagelib/contracts/uln/dvn/MultiSig.sol` — `verifySignatures()`
- `messagelib/contracts/uln/ReceiveUlnBase.sol` — `_verify()` (does it overwrite or take max?)
- Existing test: `test/audit/02_SignatureReplay.t.sol`

---

## PRIORITY 4: AV5 - Access Control Escalation (MEDIUM potential, up to $25K)

### Why This Is #4

The delegate model is intentionally powerful — a delegate has **identical privileges** to the OApp itself for ALL endpoint operations (setSendLibrary, setReceiveLibrary, setConfig, skip, nilify, burn, clear). This is by design. The bug would need to show that delegation itself has a flaw, not that delegates are powerful.

### Exact Code to Exploit

**EndpointV2.sol — Authorization (lines 354-357):**
```solidity
function _assertAuthorized(address _oapp) internal view {
    if (msg.sender != _oapp && msg.sender != delegates[_oapp]) revert Errors.LZ_Unauthorized();
}
```

**EndpointV2.sol — setDelegate (lines 327-330):**
```solidity
function setDelegate(address _delegate) external {
    delegates[msg.sender] = _delegate; // msg.sender sets their OWN delegate
}
```

### Attack Hypotheses to Test

1. **Delegate + AV1 chain**: Compromised delegate sets `confirmations = NIL_CONFIRMATIONS` AND `requiredDVNCount = NIL_DVN_COUNT` with `optionalDVNThreshold = 1` on behalf of OApp. This weakens the OApp's security to minimum. Then submit a fraudulent message through the weakened config.

2. **Delegate library swap**: Delegate calls `setSendLibrary()` to route the OApp's messages through a malicious send library that steals fees or modifies message content.

3. **Delegate censorship**: Delegate calls `skip()` / `nilify()` / `burn()` to permanently block incoming messages, causing fund loss for the OApp's users.

4. **Race condition in delegate revocation**: OApp calls `setDelegate(address(0))` to revoke delegate. In the same block, delegate calls `setConfig()` to weaken security. Does the revocation take effect before or after the delegate's tx?

### Files to Read

- `protocol/contracts/EndpointV2.sol` — `_assertAuthorized()`, `setDelegate()`, `clear()`
- `protocol/contracts/MessagingChannel.sol` — `skip()`, `nilify()`, `burn()`
- `protocol/contracts/MessageLibManager.sol` — `setSendLibrary()`, `setReceiveLibrary()`, `setConfig()`
- Existing test: `test/audit/05_AccessControl.t.sol`

---

## PRIORITY 5: AV8 - DVN Arbitrary Call via execute() (LOW-MEDIUM potential)

### Why This Is #5

DVN.execute() allows calling ANY target with ANY callData. If the DVN holds tokens (fee accumulation), a compromised signer can approve an attacker to drain them. However, this requires compromised signer keys, which is a trust assumption. The bug would need to bypass the signer requirement.

### Attack Hypotheses to Test

1. **Token drain without signer compromise**: Is there any way to call `execute()` without valid signatures? The function is `onlyRole(ADMIN_ROLE)` — can admin bypass signature verification?
   - Answer from research: No. Admin role gates the entry, but `verifySignatures()` is always called. Both checks must pass.

2. **Self-reference exploitation**: Can `execute()` call back into the DVN's `setSigner()` or `setQuorum()` to weaken security? These require `onlySelf` modifier — but `execute()` uses `target.call()` where msg.sender is the calling admin, NOT the DVN itself. So this should fail.

3. **Fee drainage via withdrawFeeFromUlnV2**: Sign instruction targeting ULNv2's `withdrawNative()`. If DVN has accumulated native fees in ULNv2, signer quorum can drain them.

### Files to Read

- `messagelib/contracts/uln/dvn/DVN.sol` — `execute()`, `quorumChangeAdmin()`, `withdrawFeeFromUlnV2()`
- Existing test: `test/audit/08_LzTokenDrain.t.sol`

---

## PRIORITY 6: AV7 - Reentrancy (LOW potential)

### Why This Is Last

CEI pattern is applied consistently across ALL external call paths:
- `lzReceive()`: `_clearPayload()` deletes `inboundPayloadHash` BEFORE calling receiver
- `lzCompose()`: Sets `composeQueue = RECEIVED_MESSAGE_HASH` BEFORE calling composer
- `send()`: Protected by `sendContext` modifier (reentrancy guard)

### Only Remaining Attack Surface

1. **Compose chain state confusion**: `lzReceive()` → receiver calls `sendCompose()` → executor calls `lzCompose()` → composer calls `send()`. Can the deeply nested compose chain corrupt any shared state? (Research says: unlikely, each state update is independent)

2. **Treasury reentrancy via payFee**: `_payTreasury()` makes an external call to `treasury.safeCall(payFee)` with limited gas. If treasury is malicious, it could attempt reentrancy during `send()`. But `sendContext` modifier blocks re-entry to `send()`.

### Files to Read

- `protocol/contracts/EndpointV2.sol` — `lzReceive()`, `lzCompose()`
- `protocol/contracts/MessagingComposer.sol` — `sendCompose()`, `lzCompose()`
- `protocol/contracts/MessagingContext.sol` — `sendContext` modifier
- Existing test: `test/audit/07_Reentrancy.t.sol`

---

## Execution Strategy

### Time Allocation (8-hour session)

| Priority | Vector | Time | Goal |
|----------|--------|------|------|
| **P1** | AV4 Fee Exploitation | 3 hours | Write PoC for lzToken over-withdrawal and race condition |
| **P2** | AV1 Quorum Bypass | 2 hours | Test NIL_CONFIRMATIONS + delegate config chain |
| **P3** | AV2 Signature Replay | 1.5 hours | Test confirmation downgrade and cross-DVN replay impact |
| **P4** | AV5 Access Control | 0.5 hours | Quick test of delegate + AV1/AV4 chains |
| **P5-6** | AV8, AV7 | 1 hour | Quick validation only |

### Decision Framework

For each vector:
1. **Can it cause permanent fund loss?** If no → skip (bounty requires permanent impact)
2. **Does it require trust assumption violation?** If yes → demote to observation (bounty excludes compromised keys unless protocol should defend against it)
3. **Is it already documented in prior audits?** If yes → skip (already checked: 10 audit PDFs, 0 matches for our AV3+AV6 finding, but re-check for other vectors)
4. **Can we write a PoC that demonstrates fund loss?** If no → don't submit

### What Constitutes a Finding

- **CRITICAL ($100K+)**: Direct theft or permanent locking of user funds in core protocol without trust assumption violation
- **HIGH ($25K-$250K)**: Theft of unclaimed yield/fees, temporary freezing with permanent loss, protocol insolvency path
- **MEDIUM ($10K-$25K)**: Griefing with material cost, economic attack vectors, configuration manipulation
- **Observation**: Design concern that doesn't meet severity threshold (document but don't submit)

### Existing Test Infrastructure

All tests extend `AuditBase.t.sol` which provides:
- `srcFixture` / `dstFixture` — full V2 stacks (EndpointV2, SendUln302, ReceiveUln302, DVN, Executor, PriceFeed, Treasury)
- `srcEndpoint` / `dstEndpoint` — convenience aliases
- `srcDvn` / `dstDvn` — DVNs with `address(this)` as signer+admin (quorum=1)
- `_makePacket()`, `_encodeAndSplit()`, `_dvnVerify()`, `_commitVerification()` — helpers
- `SRC_EID=101`, `DST_EID=102` — chain IDs

### CHECKLIST Status

| # | Vector | Status | Next Action |
|---|--------|--------|-------------|
| AV1 | DVN Quorum Bypass | TODO | Test NIL_CONFIRMATIONS → 0 confirmations path |
| AV2 | MultiSig Signature Replay | TODO | Test confirmation downgrade via verify replay |
| AV3 | Nonce/Reverification | **FINDING** | Submitted (combined with AV6) |
| AV4 | Fee Exploitation | TODO | **START HERE** — Test lzToken accounting gap |
| AV5 | Access Control Escalation | TODO | Quick test delegate + config chains |
| AV6 | Library Grace Period Race | **FINDING** | Submitted (combined with AV3) |
| AV7 | Reentrancy | TODO | Low priority, quick validation |
| AV8 | DVN Arbitrary Call via execute() | TODO | Low priority, trust assumption |
