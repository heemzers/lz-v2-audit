# LayerZero-v2 Bug Bounty Playbook

## Reward Structure

| Severity | V2 Minimum | V1 Group 1 | V1 Group 2 | Cap |
|----------|-----------|------------|------------|-----|
| Critical | $100,000 | $250,000 or 10% funds at risk | $25,000 or 10% funds at risk | $15M |
| High | - | - | - | $250,000 |
| Medium | - | - | - | $25,000 |
| Low | - | - | - | $10,000 |

**Payment**: USDC/USDT/BUSD. KYC mandatory.

## Rules That Matter

1. **PoC required for ALL severity levels** (code, not just description)
2. **Local forks only** — mainnet/testnet testing is NOT permitted
3. **Known issues are excluded** — anything in the 111 audit PDFs in `LayerZero-v2-Audits/audits/` is ineligible
4. **OFT/ONFT impact bugs are LOW severity max** — don't waste time here for big bounties
5. **Oracle manipulation is out of scope** (except flash loan attacks)
6. **OApp misconfiguration is out of scope** — must be a protocol-level bug
7. **Temporary race conditions are out of scope** — impact must be permanent or persistent

## What Qualifies as Critical ($100K-$15M)

Direct theft of user funds OR permanent freezing of user funds in the **core protocol contracts**:
- `EndpointV2.sol` — verify, lzReceive, send, clear
- `ReceiveUln302.sol` / `ReceiveUlnBase.sol` — DVN quorum verification
- `SendUln302.sol` — message encoding, fee handling
- `MessageLibManager.sol` — library upgrades, grace periods
- `MessagingChannel.sol` — nonce management, payload storage
- `DVN.sol` / `MultiSig.sol` — signature verification, execute

The attack must show **permanent loss or locking of funds**, not just a temporary DoS.

---

## Phase 1: Validate the Confirmed Finding (AV3+AV6)

**Priority: IMMEDIATE — this is your strongest lead.**

### What We Proved

`test_AV6_3_PayloadOverwriteViaGracePeriod` confirmed that during a receive library upgrade with a grace period, the old library can overwrite payloads verified by the new library. The `_inbound()` function at `MessagingChannel.sol:45` unconditionally overwrites `inboundPayloadHash`.

### Before Submitting: Check Against Known Issues

**CRITICAL STEP** — Read these 7 EndpointV2 audit PDFs cover to cover. If this is already reported, submitting it wastes a report slot and burns credibility:

```
audits/EndpointV2-Blockian-13DEC2023.pdf
audits/EndpointV2-Certora-DEDC2023.pdf
audits/EndpointV2-CMichel-13DEC2023.pdf
audits/EndpointV2-Ottersec 14DEC2023.pdf
audits/EndpointV2-Paladin-15DEC2023.pdf
audits/EndpointV2-Windhustler-15DEC2023.pdf
audits/EndpointV2-Zellic-13DEC2023.pdf
```

Also read the DVN audits (they may cover the reverification angle):
```
audits/DVN-OtterSec-12SEPT2023.pdf
audits/DVN-Paladin-26AUG2023.pdf
audits/DVN-Zellic-25AUG2023.pdf
```

**What to look for**: Any finding mentioning "reverification", "payload overwrite", "grace period race", "_inbound overwrite", or "nonce replay". If none of the audits cover this exact attack path, proceed.

### Strengthen the PoC for Submission

The current PoC is a clean-room test. To make it submission-ready:

1. **Add realistic fund amounts.** Deploy a mock OFT-like receiver that holds tokens. Show that the payload overwrite causes token transfer to attacker instead of legitimate recipient.

2. **Demonstrate permanent fund loss.** After the overwrite:
   - Show the legitimate message can never execute (hash mismatch)
   - Show the attacker's crafted message CAN execute
   - Show that `nilify` and `burn` don't help the victim recover

3. **Quantify the attack prerequisites:**
   - Library upgrade with grace period > 0 (this happens during routine upgrades)
   - Control of DVN quorum on OLD library (this is the hard part — but the old library's DVN set may be weaker post-upgrade, or a single compromised DVN in a quorum-1 setup suffices)
   - Message verified but not yet executed (common during congestion)

4. **Write the attack narrative for Immunefi submission:**
   ```
   Title: Payload Overwrite via Grace Period Reverification Enables Permanent Fund Theft

   Severity: Critical

   Impact: An attacker controlling the DVN quorum of a deprecated-but-still-valid
   receive library can overwrite the payload hash of any verified-but-unexecuted
   message during the grace period window. This permanently locks the legitimate
   user's funds and optionally redirects them to the attacker.

   Root Cause: EndpointV2.verify() allows re-verification of already-verified
   nonces, and MessagingChannel._inbound() unconditionally overwrites the
   inboundPayloadHash. Combined with the grace period allowing two receive
   libraries to be simultaneously valid, this creates a payload substitution attack.

   Attack Path:
   1. Protocol upgrades receive library from LibA to LibB with grace period G
   2. User sends cross-chain transfer, verified by LibB (payloadHash = H_legit)
   3. Attacker (controlling LibA's DVN quorum) calls LibA.commitVerification
      with same nonce but payloadHash = H_attack
   4. LibA is still valid (grace period), so EndpointV2.verify() accepts it
   5. _inbound() overwrites stored hash from H_legit to H_attack
   6. User's original message permanently unexecutable
   7. Attacker's crafted payload now executable
   ```

### File to Edit

Enhance `06_GracePeriod.t.sol::test_AV6_3_PayloadOverwriteViaGracePeriod`:
- Add a mock ERC20 transfer as the message payload
- Show tokens going to attacker instead of intended recipient
- Show victim cannot recover via any endpoint mechanism

---

## Phase 2: Deep-Dive the Remaining Attack Vectors

Work these in priority order. Each section tells you exactly what to investigate and what a finding looks like.

### AV1: DVN Quorum Bypass — Config Resolution Edge Cases

**Target files:**
- `UlnBase.sol:74-118` (`getUlnConfig`)
- `ReceiveUlnBase.sol:90-124` (`_checkVerifiable`)

**What to investigate:**

1. **NIL_CONFIRMATIONS -> 0 confirmations path.** In `getUlnConfig()` lines 82-85: when an OApp sets `confirmations = NIL_CONFIRMATIONS` (uint64.max), the resolved config has `confirmations = 0`. Then in `_verified()`, the check `verification.confirmations >= 0` is trivially true for ANY submitted verification. **But**: this requires the OApp to explicitly set NIL_CONFIRMATIONS. Investigate whether there's a path where this happens without the OApp intending it.

2. **Default config with 0 required DVNs for an unsupported eid.** What happens if `getUlnConfig` is called for an eid that has no default config? The default config's `requiredDVNCount` would be 0, and `optionalDVNThreshold` would be 0. The `_assertAtLeastOneDVN` on line 117 should catch this — verify it does in all code paths.

3. **OApp config override to weaken security.** An OApp can set `requiredDVNCount = NIL_DVN_COUNT` (override to 0 required) while relying only on optionals. If `optionalDVNThreshold` resolves to 0 from a default config edge case, the quorum is bypassed. Map all paths through `getUlnConfig` that could produce `requiredDVNCount=0 AND optionalDVNThreshold=0`.

**What a finding looks like:** A configuration state (achievable through normal or edge-case operations) where `_checkVerifiable` returns true without ANY DVN actually verifying the message.

**Test approach:**
```solidity
// Fuzz the config resolution
function testFuzz_AV1_ConfigResolution(
    uint64 defaultConf, uint8 defaultReqCount, uint8 defaultOptCount, uint8 defaultOptThreshold,
    uint64 customConf, uint8 customReqCount, uint8 customOptCount, uint8 customOptThreshold
) public {
    // Set default config, set custom config, call getUlnConfig, assert at least one DVN
}
```

### AV2: Signature Replay — Cross-DVN and Hash Reset

**Target files:**
- `DVN.sol:176-220` (`execute`)
- `DVN.sol:370-377` (`hashCallData`)
- `DVN.sol:386-392` (`_shouldCheckHash`)
- `MultiSig.sol:93-112` (`verifySignatures`)

**What to investigate:**

1. **Cross-DVN replay for non-verify selectors.** `hashCallData` includes `vid` but NOT `address(this)`. If two DVNs share the same `vid` AND the target is an external contract (not the DVN itself), the hash is identical. For functions where `_shouldCheckHash` returns true, `usedHashes` prevents replay on the SAME DVN but not across DVNs.

   **Key question:** Can an attacker deploy a DVN with the same `vid` as a legitimate DVN? The `vid` is set at construction with no uniqueness check. If yes, signed instructions targeting external contracts can be replayed.

2. **TOCTOU: execute failure -> hash reset -> context change -> replay.** When `execute` fails (line 211), `usedHashes[hash]` is reset (line 214). The signed instruction remains valid until expiration. If an admin signs a "transfer DVN funds to treasury" instruction that fails (treasury paused), then the treasury is unpaused, ANYONE with ADMIN_ROLE can replay it. Combined with cross-DVN replay, a malicious DVN admin could replay financial instructions.

3. **Verify selector downgrade attack.** `_shouldCheckHash` skips replay protection for `verify`. A compromised DVN admin could call `execute` with a `verify` calldata that sets confirmations to 0, downgrading an already-verified message. The DVN would need to call `verify` on the receiveUln with the same header but lower confirmations. Since verify OVERWRITES the Verification struct (line 44 of ReceiveUlnBase), this could make a previously verifiable message no longer verifiable, causing a DoS.

**What a finding looks like:**
- Replay of a signed financial instruction across DVN instances = theft
- Confirmation downgrade causing permanent message blockage = fund locking

**Test approach:**
```solidity
function test_AV2_CrossDVN_FinancialReplay() public {
    // Deploy DVN_A and DVN_B with same vid
    // DVN_A admin signs: "transfer 100 ETH to treasury" (targets external contract)
    // Execute on DVN_A (succeeds, hash marked used)
    // Execute same sig on DVN_B (hash NOT used on DVN_B -> succeeds again)
    // 100 ETH drained from DVN_B
}
```

### AV3: Nonce/Reverification — Deeper Exploration

**Already confirmed the overwrite.** Now investigate:

1. **Can reverification happen without a grace period?** The current PoC uses grace period. But what if the OApp's configured receive library itself is compromised? The single library can call verify() on the same nonce with different payloads. This doesn't require a library upgrade at all — just a compromised message library.

2. **Reverification + nilify interaction.** After `nilify`, the payloadHash is set to `NIL_PAYLOAD_HASH` (0xff...ff). Can `verify` overwrite NIL_PAYLOAD_HASH? Check `_verifiable`: it checks `inboundPayloadHash != EMPTY_PAYLOAD_HASH`. NIL_PAYLOAD_HASH is not EMPTY, so YES, re-verification would overwrite the nilified state. This would un-nilify a message that was intentionally blocked.

3. **Skip + reverify interaction.** After `skip(nonce)`, `lazyInboundNonce` advances past the nonce. Now `_verifiable` checks `nonce > lazyInboundNonce` — this would be false. AND `inboundPayloadHash` is EMPTY (skip doesn't store a hash). So the second condition is also false. **Skip appears to be safe** — verify this.

**What a finding looks like:**
- Un-nilifying a message that was blocked by precrime = executing a malicious message
- Reverification without grace period (just compromised library) = simpler attack path

### AV4: Fee Exploitation — LZ Token Balance Race

**Target files:**
- `EndpointV2.sol:287-297` (`_suppliedLzToken`)

**What to investigate:**

1. **Balance-of accounting.** `_suppliedLzToken` returns `IERC20(lzToken).balanceOf(address(this))` as the supplied fee. This is the TOTAL balance, not per-transaction. If the endpoint holds any residual lzToken (from incomplete refunds, direct transfers, or fee accumulation), every subsequent sender gets to claim that balance as their "supplied" fee.

2. **Practical exploit path:**
   - Alice sends a message with `payInLzToken=true`, transfers 10 lzToken to endpoint
   - Transaction processes, but 0.5 lzToken excess is refunded to wrong address (or refund fails silently)
   - Bob sends next message with `payInLzToken=true`, transfers 0 lzToken
   - `_suppliedLzToken` returns 0.5 (the residual), so Bob gets a free ride
   - Repeat at scale

3. **Check**: does `_payToken` fully clean up the balance? If `required < supplied`, it refunds `supplied - required`. After this, the endpoint balance should be 0. But what if the `Transfer.token` refund reverts (non-standard ERC20)? The lzToken stays in the endpoint for the next person.

**What a finding looks like:** A path where lzToken accumulates in the endpoint and can be stolen or used by unauthorized parties. Severity depends on whether it's theft (critical) or just fee avoidance (medium).

**Test approach:** Deploy a mock lzToken that silently fails on transfer (returns false instead of reverting). Show residual balance exploitation.

### AV5: Access Control — Delegate Abuse

**Target files:**
- `EndpointV2.sol:327-329` (`setDelegate`)
- `EndpointV2.sol:355-357` (`_assertAuthorized`)

**What to investigate:**

1. **Delegate persistence after OApp upgrade.** If an OApp upgrades its implementation (proxy pattern), does the old delegate retain power? The delegate mapping is `delegates[oappAddress]`, where oappAddress is the proxy. So YES — the delegate persists across implementation upgrades. If the old implementation set a delegate that the new implementation doesn't know about, that delegate still has full power.

2. **Delegate + library change = total control.** A delegate can call `setSendLibrary` and `setReceiveLibrary`. Could a delegate redirect all of an OApp's messages through a malicious library? The library must be registered (onlyOwner), so this requires the endpoint owner to have registered a malicious library. Unlikely but worth documenting.

3. **Skip + burn abuse by delegate.** A malicious delegate can `skip` nonces to prevent message delivery, and `burn` verified messages to destroy them permanently. This is DoS, not theft — but if the skipped/burned messages contain token transfers, it's permanent fund locking.

**What a finding looks like:** A scenario where delegate power leads to fund theft or permanent locking that the OApp cannot recover from. Most likely through `skip` + `burn` of token-bearing messages.

### AV7: Reentrancy — Compose Chain Attack

**Target files:**
- `EndpointV2.sol:172-183` (`lzReceive`)
- `MessagingComposer.sol` (`lzCompose`, `sendCompose`)

**What to investigate:**

1. **Read MessagingComposer.sol** (we haven't read this yet). The compose flow is:
   - `lzReceive` calls receiver
   - Receiver calls `endpoint.sendCompose` to queue a composed message
   - Executor calls `endpoint.lzCompose` to deliver composed message
   - Composed message receiver gets called

2. **Reentrancy through compose.** If a composed message receiver calls `lzReceive` (executing another message), and that message also composes, you get nested execution. Check:
   - Does `lzCompose` have reentrancy protection?
   - Can a compose callback re-enter `lzCompose` for the same message?
   - Can a compose callback call `clear` or `skip` on messages that are mid-execution?

3. **State corruption via nested execution.** `MessagingContext` tracks send context (`isSendingMessage`). If `lzReceive -> receiver -> send -> lzReceive` occurs, the send context might not be properly re-entrant.

**Test approach:**
```solidity
contract MaliciousComposer {
    function lzCompose(...) external {
        // Re-enter: try to execute another message during compose
        // Or: call endpoint.clear() on a message being composed
        // Or: call endpoint.skip() to advance nonce past a pending compose
    }
}
```

### AV8: DVN Arbitrary Call — Token Drain

**Already confirmed** DVN can call arbitrary targets. Now investigate:

1. **Can DVN be tricked into approving tokens it shouldn't hold?** DVNs accumulate fees in the SendLibBase `fees` mapping, withdrawn via `withdrawFee`. But if someone sends native ETH or ERC20 directly to the DVN, the DVN.execute() can be used to drain those tokens. Check: do any standard flows result in the DVN holding tokens beyond its fee balance?

2. **DVN as proxy for protocol attacks.** Since DVN can call ANY target, a compromised DVN admin could use execute() to call:
   - `receiveUln.verify()` with manipulated confirmations
   - `endpoint.verify()` directly (if DVN has MESSAGE_LIB_ROLE somehow)
   - Any registered library's `setConfig()`

---

## Phase 3: Fuzz Testing Campaign

After exhausting manual analysis, run fuzz campaigns on the most promising targets.

### Fuzz Target 1: Config Resolution

```solidity
function testFuzz_ConfigResolution(bytes calldata configData) public {
    // Decode as UlnConfig params
    // Set various default + custom configs
    // Call getUlnConfig and verify invariant: always at least 1 DVN
}
```

### Fuzz Target 2: Nonce State Machine

```solidity
function testFuzz_NonceStateMachine(uint8[] calldata actions) public {
    // Actions: 0=verify, 1=execute, 2=skip, 3=nilify, 4=burn, 5=clear, 6=reverify
    // Apply random sequence of actions to a nonce
    // Check invariant: executed nonce cannot be re-executed
    // Check invariant: burned nonce cannot be reverified
}
```

### Fuzz Target 3: Fee Accounting

```solidity
function testFuzz_FeeAccounting(uint256[] calldata amounts) public {
    // Send multiple messages with various fee amounts
    // Verify: sum of fees[workers] + refunds == total supplied
    // Verify: no tokens stuck in endpoint
}
```

---

## Phase 4: Cross-Chain Interaction Analysis

The hardest bugs to find are in cross-chain state assumptions.

1. **Source chain sends message, destination chain upgrades library before delivery.** What happens to in-flight messages? Does the grace period cover this?

2. **Different DVN sets on different chains.** If chain A and chain B use different DVN configurations for the same path, can a message valid on A be invalid on B? Can this be exploited?

3. **EID collision.** The system uses uint32 eids. Are there eid values that cause special behavior? (e.g., eid=0, eid=type(uint32).max)

---

## Phase 5: Submission Protocol

### Before You Submit

1. **Re-read ALL 7 EndpointV2 audit PDFs** for the specific finding
2. **Search Immunefi's disclosed reports** for LayerZero
3. **Verify the finding works on the latest commit** of the in-scope repo
4. **Ensure the PoC runs on a local fork** (not testnet/mainnet)
5. **Quantify the impact in dollar terms** (e.g., "any cross-chain transfer during a library upgrade window can be redirected")

### Submission Format

```markdown
## Bug Description

[2-3 sentences describing the vulnerability]

## Impact

[Specific impact: theft of X, permanent locking of Y]
[Who is affected: all users, users of specific OApps, etc.]
[Under what conditions: library upgrade, specific config, etc.]

## Risk Breakdown

- Difficulty: [Low/Medium/High — how hard is it to execute?]
- Prerequisites: [What does the attacker need?]
- Window: [How long is the vulnerability exploitable?]

## Recommendation

[Specific code fix, 1-3 lines of what to change]

## Proof of Concept

[Foundry test that demonstrates the full attack, end to end]
[Must show: initial state -> attack -> final state with fund loss]
[Must run on local fork with `forge test --match-test testName -vvv`]

## References

[Line numbers, function names, relevant code snippets]
```

### Severity Justification for AV3+AV6

To claim Critical ($100K+), you must demonstrate:
- **Direct theft OR permanent locking** of user funds
- **Realistic attack conditions** (not a theoretical edge case)
- **Protocol-level bug** (not OApp misconfiguration)

The grace period finding qualifies because:
- Library upgrades with grace periods are **routine operational procedures**
- The old library's DVN set may be weaker (that's WHY they're upgrading)
- The payload overwrite permanently locks the user's tokens
- It's a protocol-level bug in EndpointV2.verify + MessagingChannel._inbound
- No OApp misconfiguration required

---

## Priority Order of Work

| Priority | Action | Expected Time | Expected Reward |
|----------|--------|--------------|-----------------|
| 1 | Read 7 EndpointV2 audit PDFs for AV3+AV6 | 2-3 hours | Gate check |
| 2 | Strengthen AV3+AV6 PoC with fund loss demo | 3-4 hours | $100K-$15M |
| 3 | Investigate AV3 nilify un-nilification | 1-2 hours | $100K+ if new |
| 4 | Investigate AV2 cross-DVN financial replay | 2-3 hours | $100K+ |
| 5 | Read MessagingComposer.sol for AV7 compose chain | 2-3 hours | Up to $250K |
| 6 | Fuzz config resolution for AV1 | 2-4 hours | $100K+ |
| 7 | Investigate AV4 lzToken residual balance | 1-2 hours | Up to $25K |
| 8 | Run full fuzz campaign | 4-8 hours | Unknown |

**Total estimated time to first submission: 5-7 hours (priorities 1-2)**
**Total estimated time for full audit: 20-30 hours**

---

## Commands Quick Reference

```bash
# Run all audit tests
forge test --match-path 'test/audit/*' -vvv

# Run a specific test
forge test --match-test test_AV6_3_PayloadOverwriteViaGracePeriod -vvv

# Run with gas reporting
forge test --match-path 'test/audit/*' --gas-report

# Fuzz with more runs
forge test --match-path 'test/audit/*' --fuzz-runs 10000

# Build only
forge build

# Check contract sizes
forge build --sizes
```
