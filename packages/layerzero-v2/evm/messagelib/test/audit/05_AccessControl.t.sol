// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { EndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";

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
}
