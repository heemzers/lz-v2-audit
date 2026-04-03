// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";

import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { UlnConfig } from "../../contracts/uln/UlnBase.sol";

import { PacketUtil } from "../util/Packet.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV3 - Nonce/Reverification Attack
/// @dev Target: EndpointV2.verify() + MessagingChannel._inbound()
/// @dev KEY FINDING TO INVESTIGATE:
///   _verifiable() allows re-verification of verified-but-unexecuted messages.
///   _inbound() OVERWRITES the payloadHash. A compromised receive library could:
///   1. Verify legitimate message (payloadHash A stored)
///   2. Before execution, re-verify same nonce with payloadHash B
///   3. Original message can never execute; attacker's payload is now verified
///   Guard: isValidReceiveLibrary - only configured receive library can call verify.
///   But during grace period (AV6), BOTH old and new libraries are valid.
contract NonceManipulationTest is AuditBase {

    // ==================== AV3.1: Reverification Overwrites Payload ====================

    /// @dev Demonstrate that re-verifying a nonce overwrites the stored payloadHash
    function test_AV3_1_ReverificationOverwritesPayload() public {
        // Create two different packets with the same nonce
        Packet memory packetA = _makePacket(1, address(this), address(this), "legitimate message");
        Packet memory packetB = _makePacket(1, address(this), address(this), "malicious message");

        (, bytes memory headerA, , bytes32 payloadHashA) = _encodeAndSplit(packetA);
        (, bytes memory headerB, , bytes32 payloadHashB) = _encodeAndSplit(packetB);

        // Headers should be the same (same nonce, sender, receiver, eids)
        assertEq(keccak256(headerA), keccak256(headerB), "Headers should match for same path+nonce");

        // Step 1: Verify packetA (legitimate)
        _dvnVerify(dstDvn, dstReceiveUln, headerA, payloadHashA, 1);
        _commitVerification(dstReceiveUln, headerA, payloadHashA);

        // Check payloadHash A is stored
        bytes32 storedHash = dstEndpoint.inboundPayloadHash(
            address(this),
            SRC_EID,
            bytes32(uint256(uint160(address(this)))),
            1
        );
        assertEq(storedHash, payloadHashA, "PayloadHash A should be stored");

        // Step 2: Re-verify with payloadHash B (attack)
        // This requires the receive library to call endpoint.verify again
        // _verifiable checks: nonce > lazyInboundNonce OR inboundPayloadHash != EMPTY
        // Since payloadHashA is stored (not EMPTY), the condition is met
        _dvnVerify(dstDvn, dstReceiveUln, headerA, payloadHashB, 1);
        _commitVerification(dstReceiveUln, headerA, payloadHashB);

        // Check: payloadHash should now be B (overwritten!)
        bytes32 storedHashAfter = dstEndpoint.inboundPayloadHash(
            address(this),
            SRC_EID,
            bytes32(uint256(uint160(address(this)))),
            1
        );
        assertEq(storedHashAfter, payloadHashB, "PayloadHash should be overwritten to B");
        assertTrue(storedHashAfter != payloadHashA, "Original payload hash A should be gone");

        // IMPACT: The original legitimate message with payloadHash A can NEVER be executed
        // because lzReceive checks: keccak256(guid + message) == stored payloadHash
        // The attacker's payloadHash B is now stored, so only the attacker's message can execute

        // NOTE: This requires the SAME receive library to re-verify, or a second valid library
        // during a grace period. The DVN quorum still needs to be satisfied.
    }

    // ==================== AV3.2: Reverification After Partial Execution ====================

    /// @dev Test that reverification is blocked after execution (payloadHash cleared)
    function test_AV3_2_ReverificationBlockedAfterExecution() public {
        Packet memory packet = _makePacket(1, address(this), address(this), "message");
        (bytes memory encoded, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        // Verify the packet
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _commitVerification(dstReceiveUln, header, payloadHash);

        // Execute the packet (clears payloadHash)
        Origin memory origin = Origin({
            srcEid: SRC_EID,
            sender: bytes32(uint256(uint160(address(this)))),
            nonce: 1
        });

        // Compute the payload for lzReceive (guid + message)
        bytes memory payload = new bytes(encoded.length - 81);
        for (uint256 i = 81; i < encoded.length; i++) {
            payload[i - 81] = encoded[i];
        }

        dstEndpoint.lzReceive(origin, address(this), packet.guid, packet.message, "");

        // After execution, payloadHash should be cleared (EMPTY_PAYLOAD_HASH = 0)
        bytes32 storedHash = dstEndpoint.inboundPayloadHash(
            address(this),
            SRC_EID,
            bytes32(uint256(uint160(address(this)))),
            1
        );
        assertEq(storedHash, bytes32(0), "PayloadHash should be cleared after execution");

        // Now try to re-verify: _verifiable checks
        // nonce(1) > lazyInboundNonce(1) -> false (lazyInboundNonce was updated)
        // inboundPayloadHash != EMPTY_PAYLOAD_HASH -> false (it WAS cleared)
        // So reverification should be blocked
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);

        // commitVerification should revert because endpoint.verify will revert
        vm.expectRevert(); // LZ_PathNotVerifiable
        _commitVerification(dstReceiveUln, header, payloadHash);
    }

    // ==================== AV3.3: Nonce Ordering Attack ====================

    /// @dev Test if verifying nonce N+1 before nonce N causes issues
    function test_AV3_3_OutOfOrderVerification() public {
        // Verify nonce 2 first, then nonce 1
        Packet memory packet2 = _makePacket(2, address(this), address(this), "message2");
        (, bytes memory header2, , bytes32 payloadHash2) = _encodeAndSplit(packet2);

        Packet memory packet1 = _makePacket(1, address(this), address(this), "message1");
        (, bytes memory header1, , bytes32 payloadHash1) = _encodeAndSplit(packet1);

        // Verify nonce 2 first
        _dvnVerify(dstDvn, dstReceiveUln, header2, payloadHash2, 1);
        _commitVerification(dstReceiveUln, header2, payloadHash2);

        // Verify nonce 1
        _dvnVerify(dstDvn, dstReceiveUln, header1, payloadHash1, 1);
        _commitVerification(dstReceiveUln, header1, payloadHash1);

        // Both should be stored
        bytes32 stored1 = dstEndpoint.inboundPayloadHash(
            address(this), SRC_EID, bytes32(uint256(uint160(address(this)))), 1
        );
        bytes32 stored2 = dstEndpoint.inboundPayloadHash(
            address(this), SRC_EID, bytes32(uint256(uint160(address(this)))), 2
        );

        assertEq(stored1, payloadHash1, "Nonce 1 should be stored");
        assertEq(stored2, payloadHash2, "Nonce 2 should be stored");

        // Execute nonce 1 first (required for ordered execution)
        Origin memory origin1 = Origin({
            srcEid: SRC_EID,
            sender: bytes32(uint256(uint160(address(this)))),
            nonce: 1
        });
        dstEndpoint.lzReceive(origin1, address(this), packet1.guid, packet1.message, "");

        // Then execute nonce 2
        Origin memory origin2 = Origin({
            srcEid: SRC_EID,
            sender: bytes32(uint256(uint160(address(this)))),
            nonce: 2
        });
        dstEndpoint.lzReceive(origin2, address(this), packet2.guid, packet2.message, "");

        // Both executed successfully - out-of-order verification is fine,
        // but execution must be in order (clearPayload enforces gapless nonces)
    }

    // ==================== AV3.4: Skip Preserves Already-Verified Nonces ====================

    /// @dev Verified nonces remain executable after skip() advances lazyInboundNonce past them
    function test_AV3_4_SkipPreservesVerifiedNonces() public {
        bytes32 sender32 = bytes32(uint256(uint160(address(this))));

        // Verify nonces 1 and 2
        Packet memory packet1 = _makePacket(1, address(this), address(this), "msg1");
        Packet memory packet2 = _makePacket(2, address(this), address(this), "msg2");
        (, bytes memory header1, , bytes32 payloadHash1) = _encodeAndSplit(packet1);
        (, bytes memory header2, , bytes32 payloadHash2) = _encodeAndSplit(packet2);

        _dvnVerify(dstDvn, dstReceiveUln, header1, payloadHash1, 1);
        _commitVerification(dstReceiveUln, header1, payloadHash1);
        _dvnVerify(dstDvn, dstReceiveUln, header2, payloadHash2, 1);
        _commitVerification(dstReceiveUln, header2, payloadHash2);

        // Skip nonce 3 (advancing lazyInboundNonce to 3)
        // inboundNonce = 2 (nonces 1,2 verified), so skip(3) requires 3 == 2+1 ✓
        dstEndpoint.skip(address(this), SRC_EID, sender32, 3);

        // Nonces 1 and 2 still have their payload hashes
        bytes32 stored1 = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, sender32, 1);
        bytes32 stored2 = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, sender32, 2);
        assertEq(stored1, payloadHash1, "Nonce 1 hash preserved after skip");
        assertEq(stored2, payloadHash2, "Nonce 2 hash preserved after skip");

        // Execute both - should succeed despite skip(3) having advanced lazyInboundNonce
        Origin memory origin1 = Origin({ srcEid: SRC_EID, sender: sender32, nonce: 1 });
        dstEndpoint.lzReceive(origin1, address(this), packet1.guid, packet1.message, "");

        Origin memory origin2 = Origin({ srcEid: SRC_EID, sender: sender32, nonce: 2 });
        dstEndpoint.lzReceive(origin2, address(this), packet2.guid, packet2.message, "");

        emit log("CONFIRMED: skip() preserves already-verified nonces for execution");
    }

    // ==================== AV3.5: Burn After Skip Is Permanent Tombstone ====================

    /// @dev Once burned (skip + burn), a nonce can never be re-verified or executed
    function test_AV3_5_BurnAfterSkipIsPermanent() public {
        bytes32 sender32 = bytes32(uint256(uint160(address(this))));

        // Verify nonce 1
        Packet memory packet1 = _makePacket(1, address(this), address(this), "burn_me");
        (, bytes memory header1, , bytes32 payloadHash1) = _encodeAndSplit(packet1);

        _dvnVerify(dstDvn, dstReceiveUln, header1, payloadHash1, 1);
        _commitVerification(dstReceiveUln, header1, payloadHash1);

        bytes32 storedBefore = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, sender32, 1);
        assertEq(storedBefore, payloadHash1, "Nonce 1 should be verified");

        // Skip nonce 2 to advance lazyInboundNonce past nonce 1
        // inboundNonce = 1 (nonce 1 verified), skip(2) requires 2 == 1+1 ✓
        dstEndpoint.skip(address(this), SRC_EID, sender32, 2);

        // Burn nonce 1: requires nonce(1) <= lazyInboundNonce(2) and hash != EMPTY
        dstEndpoint.burn(address(this), SRC_EID, sender32, 1, payloadHash1);

        // Hash should be EMPTY_PAYLOAD_HASH (deleted)
        bytes32 storedAfter = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, sender32, 1);
        assertEq(storedAfter, bytes32(0), "Nonce 1 hash should be cleared after burn");

        // Try to re-verify nonce 1 - should fail with LZ_PathNotVerifiable
        // _verifiable: nonce(1) > lazyInboundNonce(2) → false; hash == EMPTY → false
        _dvnVerify(dstDvn, dstReceiveUln, header1, payloadHash1, 1);
        vm.expectRevert(); // LZ_PathNotVerifiable
        _commitVerification(dstReceiveUln, header1, payloadHash1);

        emit log("CONFIRMED: burn() creates permanent tombstone - re-verification impossible");
    }

    // ==================== AV3.6: Nilify Then Reverify (Recovery Path) ====================

    /// @dev Nilified nonces can be re-verified as a recovery mechanism
    function test_AV3_6_NilifyThenReverify() public {
        bytes32 sender32 = bytes32(uint256(uint160(address(this))));

        // Verify nonce 1
        Packet memory packet1 = _makePacket(1, address(this), address(this), "recover_me");
        (, bytes memory header1, , bytes32 payloadHash1) = _encodeAndSplit(packet1);

        _dvnVerify(dstDvn, dstReceiveUln, header1, payloadHash1, 1);
        _commitVerification(dstReceiveUln, header1, payloadHash1);

        // Nilify nonce 1
        dstEndpoint.nilify(address(this), SRC_EID, sender32, 1, payloadHash1);

        bytes32 nilHash = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, sender32, 1);
        assertEq(nilHash, bytes32(type(uint256).max), "Nonce 1 should be NIL_PAYLOAD_HASH");

        // Re-verify with same payload hash - should succeed
        // _verifiable: nonce(1) > lazyInboundNonce(0) → true
        // Also: NIL_PAYLOAD_HASH != EMPTY_PAYLOAD_HASH → true (condition B)
        _dvnVerify(dstDvn, dstReceiveUln, header1, payloadHash1, 1);
        _commitVerification(dstReceiveUln, header1, payloadHash1);

        bytes32 restored = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, sender32, 1);
        assertEq(restored, payloadHash1, "Nonce 1 hash should be restored after re-verify");

        // Execute - should succeed now
        Origin memory origin1 = Origin({ srcEid: SRC_EID, sender: sender32, nonce: 1 });
        dstEndpoint.lzReceive(origin1, address(this), packet1.guid, packet1.message, "");

        emit log("CONFIRMED: nilify() allows re-verification as recovery mechanism");
    }

    // ==================== AV3.7: Execution Blocked By Nonce Gap ====================

    /// @dev Out-of-order verification is fine, but execution requires contiguous nonces
    function test_AV3_7_ExecutionBlockedByGap() public {
        bytes32 sender32 = bytes32(uint256(uint160(address(this))));

        // Verify nonces 1 and 3 (skip nonce 2)
        Packet memory packet1 = _makePacket(1, address(this), address(this), "first");
        Packet memory packet3 = _makePacket(3, address(this), address(this), "third");
        (, bytes memory header1, , bytes32 payloadHash1) = _encodeAndSplit(packet1);
        (, bytes memory header3, , bytes32 payloadHash3) = _encodeAndSplit(packet3);

        _dvnVerify(dstDvn, dstReceiveUln, header1, payloadHash1, 1);
        _commitVerification(dstReceiveUln, header1, payloadHash1);
        _dvnVerify(dstDvn, dstReceiveUln, header3, payloadHash3, 1);
        _commitVerification(dstReceiveUln, header3, payloadHash3);

        // Try to execute nonce 3 - blocked by missing nonce 2
        Origin memory origin3 = Origin({ srcEid: SRC_EID, sender: sender32, nonce: 3 });
        vm.expectRevert(); // LZ_InvalidNonce(2)
        dstEndpoint.lzReceive(origin3, address(this), packet3.guid, packet3.message, "");

        // Execute nonce 1 - works fine
        Origin memory origin1 = Origin({ srcEid: SRC_EID, sender: sender32, nonce: 1 });
        dstEndpoint.lzReceive(origin1, address(this), packet1.guid, packet1.message, "");

        // Nonce 3 still blocked - nonce 2 gap remains
        vm.expectRevert(); // LZ_InvalidNonce(2)
        dstEndpoint.lzReceive(origin3, address(this), packet3.guid, packet3.message, "");

        // Fill the gap: verify nonce 2
        Packet memory packet2 = _makePacket(2, address(this), address(this), "second");
        (, bytes memory header2, , bytes32 payloadHash2) = _encodeAndSplit(packet2);
        _dvnVerify(dstDvn, dstReceiveUln, header2, payloadHash2, 1);
        _commitVerification(dstReceiveUln, header2, payloadHash2);

        // Now execute nonces 2 and 3 - both succeed
        Origin memory origin2 = Origin({ srcEid: SRC_EID, sender: sender32, nonce: 2 });
        dstEndpoint.lzReceive(origin2, address(this), packet2.guid, packet2.message, "");
        dstEndpoint.lzReceive(origin3, address(this), packet3.guid, packet3.message, "");

        emit log("CONFIRMED: Ordered execution enforced - gaps block delivery until filled");
    }
}
