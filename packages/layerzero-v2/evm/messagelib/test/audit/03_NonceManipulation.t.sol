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
}
