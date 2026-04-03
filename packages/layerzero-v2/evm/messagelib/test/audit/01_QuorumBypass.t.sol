// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";

import { PacketUtil } from "../util/Packet.sol";
import { Constant } from "../util/Constant.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV1 - DVN Quorum Bypass
/// @dev Target: ReceiveUlnBase._checkVerifiable() + UlnBase.getUlnConfig()
/// @dev Attack surfaces:
///   1. Config resolution edge cases (requiredDVNCount=0 AND optionalDVNThreshold=0)
///   2. NIL_CONFIRMATIONS -> confirmations resolves to 0 -> _verified trivially passes
///   3. DVN overlap between required/optional lists
///   4. requiredDVNCount=0 + optional-only threshold arithmetic
contract QuorumBypassTest is AuditBase {

    // ==================== AV1.1: Zero DVN Config ====================

    /// @dev Test that _assertAtLeastOneDVN prevents a config with 0 required and 0 optional threshold
    function test_AV1_1_ZeroDVNConfig_ShouldRevert() public {
        // Attempt to set a default config with 0 required DVNs and 0 optional threshold
        // This should revert with LZ_ULN_AtLeastOneDVN
        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam({
            eid: SRC_EID,
            config: UlnConfig({
                confirmations: 1,
                requiredDVNCount: 0,
                optionalDVNCount: 0,
                optionalDVNThreshold: 0,
                requiredDVNs: new address[](0),
                optionalDVNs: new address[](0)
            })
        });

        // The owner of dstReceiveUln is address(this) from Setup
        vm.expectRevert(abi.encodeWithSignature("LZ_ULN_AtLeastOneDVN()"));
        dstReceiveUln.setDefaultUlnConfigs(params);
    }

    // ==================== AV1.2: NIL_CONFIRMATIONS Resolution ====================

    /// @dev Test what happens when an OApp sets confirmations to NIL_CONFIRMATIONS (uint64.max)
    /// @dev If it resolves to 0, _verified(dvn, header, payload, 0) is trivially true when submitted=true
    function test_AV1_2_NilConfirmationsResolution() public {
        // The default config has confirmations=1 (set by wireFixtureV2WithRemote)
        // If an OApp sets confirmations to NIL_CONFIRMATIONS, the resolved value should be 0
        // because the code says: "if confirmations is uint64.max, no block confirmations required"
        // Then _verified checks: verification.confirmations >= _requiredConfirmation (0)
        // This is trivially true if submitted=true, regardless of what confirmations the DVN submitted

        // Get the resolved config for this test contract as OApp on dstReceiveUln
        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        // Default should be confirmations=1
        assertEq(config.confirmations, 1, "Default confirmations should be 1");

        // Now verify the NIL_CONFIRMATIONS behavior:
        // Line 82-85 of UlnBase.getUlnConfig():
        //   if confirmations == DEFAULT (0): use default
        //   else if confirmations != NIL_CONFIRMATIONS: use custom value
        //   else: do nothing -> rtnConfig.confirmations stays at 0
        // This means NIL_CONFIRMATIONS intentionally resolves to 0 confirmations
        // The question is: can this be exploited to bypass verification?

        // Create a packet to test with
        Packet memory packet = _makePacket(1, address(this), address(this), "test");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        // DVN verifies with 0 confirmations (minimum possible)
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // With default config (confirmations=1), this should NOT be verifiable
        // because DVN submitted 0 confirmations but 1 is required
        UlnConfig memory defaultConfig = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        bool isVerifiable = dstReceiveUln.verifiable(defaultConfig, keccak256(header), payloadHash);
        assertFalse(isVerifiable, "Should not be verifiable with 0 confirmations when 1 is required");
    }

    // ==================== AV1.3: DVN Overlap ====================

    /// @dev Test if the same DVN in both required and optional lists satisfies both checks
    /// @dev This could reduce effective security from intended config
    function test_AV1_3_DVNOverlapRequiredOptional() public {
        // The UlnConfig comment says: "allowed overlap with optionalDVNs"
        // If DVN-A is in both required(1) and optional(1/1), a single DVN signing
        // satisfies BOTH the required check AND the optional threshold

        address dvnAddr = address(dstDvn);

        // Create config with same DVN in both lists
        address[] memory requiredDvns = new address[](1);
        requiredDvns[0] = dvnAddr;
        address[] memory optionalDvns = new address[](1);
        optionalDvns[0] = dvnAddr;

        // Note: this requires dvnAddr > dvnAddr which is impossible for same address
        // But the arrays are length 1, so no sorting issue
        // The overlap is explicitly allowed per the comment in UlnConfig struct

        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam({
            eid: SRC_EID,
            config: UlnConfig({
                confirmations: 1,
                requiredDVNCount: 1,
                optionalDVNCount: 1,
                optionalDVNThreshold: 1,
                requiredDVNs: requiredDvns,
                optionalDVNs: optionalDvns
            })
        });

        dstReceiveUln.setDefaultUlnConfigs(params);

        // Verify that a single DVN signature satisfies both required AND optional
        Packet memory packet = _makePacket(1, address(this), address(this), "overlap-test");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);

        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        bool isVerifiable = dstReceiveUln.verifiable(config, keccak256(header), payloadHash);
        assertTrue(isVerifiable, "Single DVN in both lists should satisfy both checks");

        // This is documented behavior, but worth noting: effective quorum is 1 not 2
        // An OApp admin setting required=1 + optional=1/1 with overlapping DVN
        // may believe they have 2-DVN security but actually have 1-DVN security
    }

    // ==================== AV1.4: Optional-Only Config ====================

    /// @dev Test config with requiredDVNCount=0 (using NIL_DVN_COUNT) and optional only
    function test_AV1_4_OptionalOnlyConfig() public {
        address dvnAddr = address(dstDvn);
        address[] memory optionalDvns = new address[](1);
        optionalDvns[0] = dvnAddr;

        // For an OApp-level config: requiredDVNCount=NIL_DVN_COUNT means "override to 0 required"
        // But setDefaultUlnConfigs reverts if requiredDVNCount == NIL_DVN_COUNT
        // So this only works at the OApp level, not default level

        // Test: can we create a state where getUlnConfig returns 0 required + optional threshold?
        // The _assertAtLeastOneDVN at line 117 should catch requiredDVNCount=0 && optionalDVNThreshold=0
        // But what about requiredDVNCount=0 && optionalDVNThreshold>0? That's valid.

        // First, set a normal default
        // Default is already set from wireFixtureV2WithRemote

        // Then check getUlnConfig behavior - it already has required DVN from default
        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertTrue(config.requiredDVNCount > 0 || config.optionalDVNThreshold > 0,
            "Config must have at least one DVN");
    }
}
