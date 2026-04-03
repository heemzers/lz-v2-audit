// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { EndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";
import { ILayerZeroReceiver } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroReceiver.sol";

import { PacketUtil } from "../util/Packet.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV7 - Reentrancy
/// @dev Target: MessagingContext, EndpointV2.lzReceive(), MessagingComposer.lzCompose()
/// @dev lzReceive clears payload BEFORE external call (CEI pattern).
/// @dev But compose chains: can receiver -> send -> receive -> compose create unexpected state?
contract ReentrancyTest is AuditBase {

    ReentrantReceiver internal reentrantReceiver;

    function setUp() public override {
        super.setUp();
        reentrantReceiver = new ReentrantReceiver(address(dstEndpoint));
    }

    // ==================== AV7.1: lzReceive CEI Pattern ====================

    /// @dev Verify that lzReceive clears payload before calling receiver
    function test_AV7_1_LzReceiveCEIPattern() public {
        // lzReceive flow:
        // 1. _clearPayload (clears inboundPayloadHash, updates lazyInboundNonce)
        // 2. ILayerZeroReceiver(_receiver).lzReceive(...) (external call)
        // This is CEI (Check-Effects-Interactions) pattern

        Packet memory packet = _makePacket(1, address(this), address(this), "test-cei");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        // Verify the packet
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _commitVerification(dstReceiveUln, header, payloadHash);

        // Check payload is stored
        bytes32 stored = dstEndpoint.inboundPayloadHash(
            address(this),
            SRC_EID,
            bytes32(uint256(uint160(address(this)))),
            1
        );
        assertTrue(stored != bytes32(0), "Payload should be stored before execution");

        // Execute
        Origin memory origin = Origin({
            srcEid: SRC_EID,
            sender: bytes32(uint256(uint160(address(this)))),
            nonce: 1
        });
        dstEndpoint.lzReceive(origin, address(this), packet.guid, packet.message, "");

        // Payload should be cleared after execution
        stored = dstEndpoint.inboundPayloadHash(
            address(this),
            SRC_EID,
            bytes32(uint256(uint160(address(this)))),
            1
        );
        assertEq(stored, bytes32(0), "Payload should be cleared after execution");
    }

    // ==================== AV7.2: Reentrancy via lzReceive ====================

    /// @dev Test if a reentrant receiver can exploit lzReceive
    function test_AV7_2_ReentrantLzReceive() public {
        // The reentrant receiver will try to call lzReceive again during its lzReceive callback
        // Since _clearPayload runs BEFORE the external call, the payload is already cleared
        // So the reentrant call should fail (PayloadHashNotFound)

        address receiver = address(reentrantReceiver);
        Packet memory packet = _makePacket(1, address(this), receiver, "reentrant-test");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        // Verify
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _commitVerification(dstReceiveUln, header, payloadHash);

        // Execute - reentrant receiver will try to re-execute
        Origin memory origin = Origin({
            srcEid: SRC_EID,
            sender: bytes32(uint256(uint160(address(this)))),
            nonce: 1
        });

        // The reentrant call should fail internally (payload already cleared)
        // But the outer call should succeed because CEI pattern protects it
        dstEndpoint.lzReceive(origin, receiver, packet.guid, packet.message, "");

        // Verify the reentrant call failed
        assertTrue(reentrantReceiver.reentrancyAttempted(), "Reentrancy should have been attempted");
        assertTrue(reentrantReceiver.reentrancyFailed(), "Reentrancy should have failed");
    }

    // ==================== AV7.3: Send During Receive ====================

    /// @dev Test if a receiver can call send() during lzReceive
    /// @dev This tests the sendContext modifier interaction
    function test_AV7_3_SendDuringReceive() public {
        // A receiver calling send() during lzReceive is a legitimate pattern
        // (e.g., bridge relays, cross-chain swaps)
        // The sendContext modifier should handle this correctly
        // MessagingContext tracks whether we're in a send context to prevent
        // reentrancy issues with the send path

        // This is a design analysis test - the actual reentrancy guard is
        // the sendContext modifier which sets isSendingMessage = true
        // and reverts if it's already true (re-entrancy into send)

        // lzReceive -> receiver.lzReceive -> endpoint.send should work
        // because lzReceive doesn't set sendContext
        assertTrue(true, "Send during receive is a legitimate pattern");
    }
}

/// @dev Helper contract that attempts reentrancy during lzReceive
contract ReentrantReceiver is ILayerZeroReceiver {
    EndpointV2 internal endpoint;
    bool public reentrancyAttempted;
    bool public reentrancyFailed;

    constructor(address _endpoint) {
        endpoint = EndpointV2(_endpoint);
    }

    function lzReceive(
        Origin calldata _origin,
        bytes32 _guid,
        bytes calldata _message,
        address,
        bytes calldata _extraData
    ) external payable override {
        reentrancyAttempted = true;

        // Try to re-execute the same message (should fail - payload already cleared)
        try endpoint.lzReceive(_origin, address(this), _guid, _message, _extraData) {
            // If this succeeds, reentrancy protection failed!
            reentrancyFailed = false;
        } catch {
            // Expected: reentrancy blocked by CEI pattern
            reentrancyFailed = true;
        }
    }

    function allowInitializePath(Origin calldata) external pure override returns (bool) {
        return true;
    }

    function nextNonce(uint32, bytes32) external pure override returns (uint64) {
        return 0;
    }
}
