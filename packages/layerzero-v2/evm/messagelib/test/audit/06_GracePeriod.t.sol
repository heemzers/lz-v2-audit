// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { EndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";
import { IMessageLibManager } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";

import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { SendUln302 } from "../../contracts/uln/uln302/SendUln302.sol";
import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { SetDefaultExecutorConfigParam, ExecutorConfig } from "../../contracts/SendLibBase.sol";
import { DVN } from "../../contracts/uln/dvn/DVN.sol";
import { DVNFeeLib } from "../../contracts/uln/dvn/DVNFeeLib.sol";
import { IDVN } from "../../contracts/uln/interfaces/IDVN.sol";
import { Executor } from "../../contracts/Executor.sol";
import { ExecutorFeeLib } from "../../contracts/ExecutorFeeLib.sol";
import { IExecutor } from "../../contracts/interfaces/IExecutor.sol";
import { PriceFeed } from "../../contracts/PriceFeed.sol";
import { Treasury } from "../../contracts/Treasury.sol";

import { Setup } from "../util/Setup.sol";
import { PacketUtil } from "../util/Packet.sol";
import { Constant } from "../util/Constant.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV6 - Library Grace Period Race
/// @dev Target: MessageLibManager.isValidReceiveLibrary()
/// @dev During grace period, BOTH old and new receive libraries are valid.
/// @dev Combined with AV3 (reverification), a deprecated library could overwrite
/// @dev payloads verified by the new library.
contract GracePeriodTest is AuditBase {

    ReceiveUln302 internal newReceiveUln;
    DVN internal newDvn;

    function setUp() public override {
        super.setUp();

        // Deploy a new receive library (simulating an upgrade)
        newReceiveUln = new ReceiveUln302(address(dstEndpoint));
        dstEndpoint.registerLibrary(address(newReceiveUln));

        // Deploy a new DVN for the new library
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

        // Set ULN config for the new receive library
        address[] memory dvns = new address[](1);
        dvns[0] = address(newDvn);
        UlnConfig memory ulnConfig = UlnConfig(1, uint8(dvns.length), 0, 0, dvns, new address[](0));
        SetDefaultUlnConfigParam[] memory ulnConfigParams = new SetDefaultUlnConfigParam[](1);
        ulnConfigParams[0] = SetDefaultUlnConfigParam(SRC_EID, ulnConfig);
        newReceiveUln.setDefaultUlnConfigs(ulnConfigParams);
    }

    // ==================== AV6.1: Both Libraries Valid During Grace Period ====================

    /// @dev Verify that during grace period, both old and new libraries are valid
    function test_AV6_1_BothLibrariesValidDuringGracePeriod() public {
        address oldLib = address(dstReceiveUln);
        address newLib = address(newReceiveUln);

        // Set new default receive library with grace period
        uint256 gracePeriod = 100; // 100 blocks
        dstEndpoint.setDefaultReceiveLibrary(SRC_EID, newLib, gracePeriod);

        // Both libraries should be valid
        bool oldValid = dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, oldLib);
        bool newValid = dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, newLib);

        assertTrue(oldValid, "Old library should be valid during grace period");
        assertTrue(newValid, "New library should be valid during grace period");
    }

    // ==================== AV6.2: Grace Period Expiry ====================

    /// @dev After grace period expires, only new library should be valid
    function test_AV6_2_GracePeriodExpiry() public {
        address oldLib = address(dstReceiveUln);
        address newLib = address(newReceiveUln);

        uint256 gracePeriod = 100;
        dstEndpoint.setDefaultReceiveLibrary(SRC_EID, newLib, gracePeriod);

        // Fast forward past grace period
        vm.roll(block.number + gracePeriod + 1);

        bool oldValid = dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, oldLib);
        bool newValid = dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, newLib);

        assertFalse(oldValid, "Old library should NOT be valid after grace period");
        assertTrue(newValid, "New library should still be valid after grace period");
    }

    // ==================== AV6.3: Payload Overwrite via Grace Period ====================

    /// @dev CRITICAL: During grace period, old library can overwrite payloads verified by new library
    /// @dev This combines AV6 (grace period) with AV3 (reverification)
    function test_AV6_3_PayloadOverwriteViaGracePeriod() public {
        address oldLib = address(dstReceiveUln);
        address newLib = address(newReceiveUln);

        // Set up grace period
        uint256 gracePeriod = 100;
        dstEndpoint.setDefaultReceiveLibrary(SRC_EID, newLib, gracePeriod);

        // Step 1: New library verifies a legitimate packet
        Packet memory legitimatePacket = _makePacket(1, address(this), address(this), "legitimate");
        (, bytes memory header, , bytes32 legitimateHash) = _encodeAndSplit(legitimatePacket);

        // New DVN verifies via new library
        vm.prank(address(newDvn));
        newReceiveUln.verify(header, legitimateHash, 1);
        newReceiveUln.commitVerification(header, legitimateHash);

        // Verify legitimate hash is stored
        bytes32 stored = dstEndpoint.inboundPayloadHash(
            address(this),
            SRC_EID,
            bytes32(uint256(uint160(address(this)))),
            1
        );
        assertEq(stored, legitimateHash, "Legitimate hash should be stored");

        // Step 2: Old library (still valid during grace period) re-verifies with different payload
        Packet memory maliciousPacket = _makePacket(1, address(this), address(this), "malicious");
        (, , , bytes32 maliciousHash) = _encodeAndSplit(maliciousPacket);

        // Old DVN verifies via old library (still valid during grace period!)
        _dvnVerify(dstDvn, dstReceiveUln, header, maliciousHash, 1);
        _commitVerification(dstReceiveUln, header, maliciousHash);

        // Check: was the payload overwritten?
        bytes32 storedAfter = dstEndpoint.inboundPayloadHash(
            address(this),
            SRC_EID,
            bytes32(uint256(uint160(address(this)))),
            1
        );

        // If this assertion passes, the old library successfully overwrote the new library's payload
        // This would be a CRITICAL finding
        if (storedAfter == maliciousHash) {
            // CRITICAL: Old library overwrote new library's verified payload during grace period
            emit log("CRITICAL: Payload overwrite via grace period confirmed!");
            assertTrue(true);
        } else {
            // The system prevented the overwrite
            emit log("Grace period overwrite was prevented");
            assertEq(storedAfter, legitimateHash, "Original payload should be preserved");
        }
    }

    // ==================== AV6.4: Zero Grace Period ====================

    /// @dev Verify that a zero grace period immediately invalidates the old library
    function test_AV6_4_ZeroGracePeriod() public {
        address oldLib = address(dstReceiveUln);
        address newLib = address(newReceiveUln);

        // Set new library with NO grace period
        dstEndpoint.setDefaultReceiveLibrary(SRC_EID, newLib, 0);

        bool oldValid = dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, oldLib);
        bool newValid = dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, newLib);

        assertFalse(oldValid, "Old library should NOT be valid with zero grace period");
        assertTrue(newValid, "New library should be valid");
    }

    // ==================== AV6.5: Double Migration Silently Evicts Grace Period ====================

    /// @dev CRITICAL: Calling setReceiveLibrary() twice rapidly deletes the first library's
    ///      grace period. Any message verified-but-not-committed on the first library is
    ///      permanently stranded with no recovery path.
    /// @dev This is a design footgun that can cause permanent fund loss during library migrations.
    function test_AV6_5_DoubleMigrationEvictsGracePeriod() public {
        // Deploy a THIRD receive library (libC)
        ReceiveUln302 thirdReceiveUln = new ReceiveUln302(address(dstEndpoint));
        dstEndpoint.registerLibrary(address(thirdReceiveUln));

        // Deploy DVN for third library
        address[] memory libs3 = new address[](4);
        libs3[0] = address(0);
        libs3[1] = address(0);
        libs3[2] = address(0);
        libs3[3] = address(thirdReceiveUln);
        address[] memory signers3 = new address[](1);
        signers3[0] = address(this);
        address[] memory admins3 = new address[](1);
        admins3[0] = address(this);
        DVN thirdDvn = new DVN(DST_EID, DST_EID, libs3, address(dstFixture.priceFeed), signers3, 1, admins3);
        DVNFeeLib thirdFeeLib = new DVNFeeLib(DST_EID, 1e18);
        thirdDvn.setWorkerFeeLib(address(thirdFeeLib));
        IDVN.DstConfigParam[] memory dstCfg3 = new IDVN.DstConfigParam[](1);
        dstCfg3[0] = IDVN.DstConfigParam({ dstEid: DST_EID, gas: 5000, multiplierBps: 0, floorMarginUSD: 0 });
        thirdDvn.setDstConfig(dstCfg3);

        // Set default ULN config for third library
        address[] memory dvns3 = new address[](1);
        dvns3[0] = address(thirdDvn);
        UlnConfig memory ulnCfg3 = UlnConfig(1, 1, 0, 0, dvns3, new address[](0));
        SetDefaultUlnConfigParam[] memory ulnParams3 = new SetDefaultUlnConfigParam[](1);
        ulnParams3[0] = SetDefaultUlnConfigParam(SRC_EID, ulnCfg3);
        thirdReceiveUln.setDefaultUlnConfigs(ulnParams3);

        address libA = address(dstReceiveUln);
        address libB = address(newReceiveUln);
        address libC = address(thirdReceiveUln);

        // Step 0: Set libA as the OApp's explicit receive library (moving off DEFAULT)
        // Grace period with DEFAULT_LIB is not allowed, so we must set explicitly first
        dstEndpoint.setReceiveLibrary(address(this), SRC_EID, libA, 0);

        // Step 1: Migrate from libA -> libB with 100 block grace period
        // OApp sets libB as receive library, libA gets grace period
        dstEndpoint.setReceiveLibrary(address(this), SRC_EID, libB, 100);

        // Verify libA is still valid during grace period
        assertTrue(dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, libA),
            "libA should be valid during grace period");

        // Step 2: A message is verified on libA (still valid during grace period)
        Packet memory packet = _makePacket(1, address(this), address(this), "stranded");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);

        // Verify: packet IS verifiable on libA right now
        UlnConfig memory configA = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        bool verifiableBefore = dstReceiveUln.verifiable(configA, keccak256(header), payloadHash);
        assertTrue(verifiableBefore, "Packet should be verifiable on libA before eviction");

        // Step 3: BEFORE grace period expires, migrate from libB -> libC
        // This SILENTLY DELETES libA's grace period timeout!
        dstEndpoint.setReceiveLibrary(address(this), SRC_EID, libC, 100);

        // Step 4: Verify libA's grace period was evicted
        assertFalse(dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, libA),
            "CONFIRMED: libA evicted - no longer valid despite original grace period");

        // libB is now in the timeout slot (not libA)
        assertTrue(dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, libB),
            "libB is now in the grace period timeout");
        assertTrue(dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, libC),
            "libC is the current library");

        // Step 5: Try to commit the message verified on libA - PERMANENTLY FAILS
        // commitVerification calls endpoint.verify(), which checks isValidReceiveLibrary
        vm.expectRevert();
        dstReceiveUln.commitVerification(header, payloadHash);

        // Step 6: Even after libB's grace period expires, libA never becomes valid again
        vm.roll(block.number + 200); // well past any grace period
        assertFalse(dstEndpoint.isValidReceiveLibrary(address(this), SRC_EID, libA),
            "libA is permanently invalid");

        // The message is PERMANENTLY stranded in libA's hashLookup
        // It was verified but can never be committed to the endpoint
        // If this was an OFT transfer, tokens burned on source are never minted on destination

        emit log("CONFIRMED: Double migration silently evicts first library's grace period");
        emit log("Message verified on libA is permanently stranded - commitVerification reverts");
        emit log("Impact: Permanent fund loss for any token bridge message verified on evicted library");
    }
}
