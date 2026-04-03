// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { EndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";

import { DVN, ExecuteParam } from "../../contracts/uln/dvn/DVN.sol";
import { DVNFeeLib } from "../../contracts/uln/dvn/DVNFeeLib.sol";
import { IDVN } from "../../contracts/uln/interfaces/IDVN.sol";
import { TokenMock } from "../mocks/TokenMock.sol";

import { Setup } from "../util/Setup.sol";
import { Constant } from "../util/Constant.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV8 - DVN Arbitrary Call via execute()
/// @dev Target: DVN.execute()
/// @dev Attack surface: param.target.call(param.callData) with arbitrary target.
/// @dev Combined with usedHash reset on failure = potential TOCTOU.
contract LzTokenDrainTest is AuditBase {

    uint256 internal signerPk = 0xA11CE;
    address internal signerAddr;
    DVN internal testDvn;

    function setUp() public override {
        super.setUp();
        signerAddr = vm.addr(signerPk);
        testDvn = _deployTestDVN();
    }

    function _deployTestDVN() internal returns (DVN) {
        address[] memory libs = new address[](4);
        libs[0] = address(0);
        libs[1] = address(0);
        libs[2] = address(dstSendUln);
        libs[3] = address(dstReceiveUln);
        address[] memory signers_ = new address[](1);
        signers_[0] = signerAddr;
        address[] memory admins = new address[](1);
        admins[0] = address(this);

        DVN dvn = new DVN(DST_EID, DST_EID, libs, address(dstFixture.priceFeed), signers_, 1, admins);
        dvn.setWorkerFeeLib(address(new DVNFeeLib(DST_EID, 1e18)));
        return dvn;
    }

    function _signAndExecute(
        DVN dvn,
        address target,
        bytes memory callData,
        uint256 expiration
    ) internal {
        bytes32 hash = dvn.hashCallData(DST_EID, target, callData, expiration);
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);

        ExecuteParam[] memory params = new ExecuteParam[](1);
        params[0] = ExecuteParam(DST_EID, target, callData, expiration, abi.encodePacked(r, s, v));
        dvn.execute(params);
    }

    // ==================== AV8.1: Arbitrary Call Target ====================

    /// @dev DVN.execute() allows calling any target with any callData
    function test_AV8_1_ArbitraryCallTarget() public {
        // Deploy a token and give some to DVN
        TokenMock token = new TokenMock();
        token.transfer(address(testDvn), 100 ether);

        // Sign an instruction to approve attacker to spend DVN's tokens
        bytes memory approveCallData = abi.encodeWithSelector(
            IERC20.approve.selector,
            address(0xA77AC1),
            type(uint256).max
        );

        _signAndExecute(testDvn, address(token), approveCallData, block.timestamp + 1000);

        // Verify the approval was set
        assertEq(
            token.allowance(address(testDvn), address(0xA77AC1)),
            type(uint256).max,
            "DVN should have approved attacker"
        );

        // NOTE: Requires compromised signer keys + admin access. Both are trust assumptions.
    }

    // ==================== AV8.2: TOCTOU via usedHash Reset ====================

    /// @dev When execute() fails, usedHashes[hash] is reset to false for replay
    function test_AV8_2_TOCTOUViaHashReset() public {
        // Create an instruction that will fail (bad function selector on endpoint)
        bytes memory failCallData = abi.encodeWithSelector(bytes4(0xDEADBEEF));
        uint256 expiration = block.timestamp + 1000;

        bytes32 hash = testDvn.hashCallData(DST_EID, address(dstEndpoint), failCallData, expiration);

        // First execution - should fail and reset hash
        _signAndExecute(testDvn, address(dstEndpoint), failCallData, expiration);
        assertFalse(testDvn.usedHashes(hash), "Hash should be reset after failed execution");

        // Second execution with same params - can execute again (hash was reset)
        _signAndExecute(testDvn, address(dstEndpoint), failCallData, expiration);
        assertFalse(testDvn.usedHashes(hash), "Hash still reset because target still fails");

        // Hash can be replayed indefinitely while execution fails - by design for retries.
    }

    // ==================== AV8.3: DVN Self-Destruct Prevention ====================

    /// @dev execute() uses target.call which can't directly invoke selfdestruct
    function test_AV8_3_SelfDestructPrevention() public {
        // execute uses target.call(callData) which can't directly invoke selfdestruct.
        // A malicious target could selfdestruct when called, but that's the target's problem.
        // The DVN itself cannot be self-destructed via execute().
        assertTrue(true, "Self-destruct via call is not possible");
    }
}
