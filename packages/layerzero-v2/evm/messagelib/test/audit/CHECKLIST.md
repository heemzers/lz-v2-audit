# Attack Vector Checklist

| # | Vector | Severity | Target | Status |
|---|--------|----------|--------|--------|
| AV1 | DVN Quorum Bypass | HIGH | ReceiveUlnBase._checkVerifiable() + UlnBase.getUlnConfig() | **FINDING** - NIL_CONFIRMATIONS bypasses finality (7 tests passing) |
| AV2 | MultiSig Signature Replay | HIGH | DVN.execute() + ReceiveUlnBase._verify() | **FINDING** - Confirmation downgrade via overwrite (5 tests passing) |
| AV3 | Nonce/Reverification Attack | CRITICAL | EndpointV2.verify() + MessagingChannel._inbound() | **FINDING** (combined with AV6) |
| AV4 | Fee Exploitation | CRITICAL | EndpointV2._suppliedLzToken() + SendLibBaseE2 | **FINDING** - Front-running theft + over-withdrawal (4 tests passing) |
| AV5 | Access Control Escalation | MEDIUM | EndpointV2._assertAuthorized() + setDelegate() | **FINDING** - Delegate chain attack (6 tests passing) |
| AV6 | Library Grace Period Race | CRITICAL | MessageLibManager.isValidReceiveLibrary() | **FINDING** (combined with AV3) |
| AV7 | Reentrancy | LOW | MessagingContext, EndpointV2.lzReceive() | TESTED - CEI pattern holds |
| AV8 | DVN Arbitrary Call via execute() | LOW | DVN.execute() target.call | TESTED - Trust assumption (requires signer keys) |

## Test Results Summary

**Total: 22 tests passing across 4 test suites**

| Suite | Tests | Status |
|-------|-------|--------|
| 01_QuorumBypass.t.sol | 7 | All PASS |
| 02_SignatureReplay.t.sol | 5 | All PASS |
| 04_FeeExploit.t.sol | 4 | All PASS |
| 05_AccessControl.t.sol | 6 | All PASS |

## Bounty Severity Assessment

### Submittable Findings (by estimated bounty value)

1. **AV4.1 LzToken Front-Running Theft** - CRITICAL ($100K+)
   - Direct theft of user funds, no trust assumption, permissionless attack
   - Root cause: `_suppliedLzToken()` uses `balanceOf` not per-sender tracking

2. **AV3+AV6 Payload Overwrite** - CRITICAL ($100K+)
   - Already submitted (permanent fund locking via grace period + reverification)

3. **AV1 NIL_CONFIRMATIONS Bypass** - HIGH ($25K-$250K)
   - Disables finality checks for OApp configs
   - Asymmetric guard: blocked for defaults, allowed for OApp configs
   - Could argue: design flaw in config validation, not trust assumption

4. **AV2 Confirmation Downgrade** - HIGH ($25K-$250K)
   - Liveness attack: DVN can retract verification
   - Requires compromised DVN keys (trust assumption weakens this)

5. **AV4.2 Treasury Over-Withdrawal** - MEDIUM ($10K-$25K)
   - Centralization risk, requires treasury owner

6. **AV5.5 Delegate Chain Attack** - MEDIUM ($10K-$25K)
   - Requires compromised delegate (trust assumption)

### Not Submittable (by design / trust assumption)
- AV7 Reentrancy: CEI pattern correctly applied
- AV8 DVN Arbitrary Call: requires signer key compromise

## Status Legend
- **FINDING**: Vulnerability confirmed with passing PoC test
- TESTED: PoC written, no exploitable finding
- TODO: Not started
