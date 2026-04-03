# Attack Vector Checklist

| # | Vector | Severity | Target | Status |
|---|--------|----------|--------|--------|
| AV1 | DVN Quorum Bypass | CRITICAL | ReceiveUlnBase._checkVerifiable() + UlnBase.getUlnConfig() | TODO |
| AV2 | MultiSig Signature Replay | CRITICAL | DVN.execute() + MultiSig.verifySignatures() | TODO |
| AV3 | Nonce/Reverification Attack | CRITICAL | EndpointV2.verify() + MessagingChannel._inbound() | FINDING (combined with AV6) |
| AV4 | Fee Exploitation | HIGH | EndpointV2._suppliedLzToken() + SendLibBase | TODO |
| AV5 | Access Control Escalation | HIGH | EndpointV2._assertAuthorized() + setDelegate() | TODO |
| AV6 | Library Grace Period Race | HIGH | MessageLibManager.isValidReceiveLibrary() | FINDING (combined with AV3) |
| AV7 | Reentrancy | HIGH | MessagingContext, EndpointV2.lzReceive() | TODO |
| AV8 | DVN Arbitrary Call via execute() | HIGH | DVN.execute() target.call | TODO |

## Status Legend
- TODO: Not started
- IN PROGRESS: Currently investigating
- TESTED: PoC written, no finding
- FINDING: Vulnerability confirmed (see FINDINGS.md)
- N/A: Not applicable / out of scope

## Key Attack Surfaces

### AV1 - DVN Quorum Bypass
- [ ] Config resolution: can getUlnConfig() return requiredDVNCount=0 AND optionalDVNThreshold=0?
- [ ] NIL_CONFIRMATIONS (uint64.max) -> confirmations resolves to 0 -> _verified trivially passes
- [ ] DVN overlap between required/optional lists
- [ ] requiredDVNCount=0 + optional-only threshold arithmetic

### AV2 - MultiSig Signature Replay
- [ ] Cross-DVN replay (shared vid)
- [ ] _shouldCheckHash bypass for verify selector
- [ ] usedHashes reset on failed execution -> TOCTOU
- [ ] Signature s-value malleability via ECDSA.tryRecover

### AV3 - Nonce/Reverification Attack
- [ ] _verifiable allows re-verification of verified-but-unexecuted messages
- [ ] _inbound OVERWRITES payloadHash on re-verification
- [ ] Grace period + re-verification = payload swap

### AV4 - Fee Exploitation
- [ ] _suppliedLzToken uses balanceOf (race condition between senders)
- [ ] Fee accumulation/withdrawal correctness

### AV5 - Access Control Escalation
- [ ] Delegate has full OApp config power
- [ ] Authorization gaps in setSendLibrary/setReceiveLibrary/skip/nilify/burn/clear

### AV6 - Library Grace Period Race
- [ ] Both old AND new receive libraries valid during grace period
- [ ] Combined with AV3: deprecated library overwrites payloads

### AV7 - Reentrancy
- [ ] lzReceive clears payload before external call (CEI) - verify
- [ ] Compose chains: receiver -> send -> receive -> compose

### AV8 - DVN Arbitrary Call via execute()
- [ ] target.call with arbitrary target + callData
- [ ] usedHash reset on failure = potential replay
