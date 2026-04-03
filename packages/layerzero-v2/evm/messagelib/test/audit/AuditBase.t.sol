// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test } from "forge-std/Test.sol";
import { BytesLib } from "solidity-bytes-utils/contracts/BytesLib.sol";

import { EndpointV2, Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";

import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { SendUln302 } from "../../contracts/uln/uln302/SendUln302.sol";
import { ReceiveUlnBase, Verification } from "../../contracts/uln/ReceiveUlnBase.sol";
import { UlnConfig, SetDefaultUlnConfigParam } from "../../contracts/uln/UlnBase.sol";
import { DVN, ExecuteParam } from "../../contracts/uln/dvn/DVN.sol";
import { Executor } from "../../contracts/Executor.sol";
import { PriceFeed } from "../../contracts/PriceFeed.sol";
import { Treasury } from "../../contracts/Treasury.sol";
import { SendLibBase, ExecutorConfig, SetDefaultExecutorConfigParam } from "../../contracts/SendLibBase.sol";

import { Setup } from "../util/Setup.sol";
import { PacketUtil } from "../util/Packet.sol";
import { Constant } from "../util/Constant.sol";
import { OptionsUtil } from "../util/OptionsUtil.sol";

/// @title AuditBase - Shared test harness for LayerZero-v2 audit PoCs
/// @dev Extends Setup.sol patterns. Deploys a full V2 stack wired to itself for easy testing.
abstract contract AuditBase is Test {
    using OptionsUtil for bytes;

    // --- Fixtures ---
    Setup.FixtureV2 internal srcFixture;
    Setup.FixtureV2 internal dstFixture;

    // --- Convenience aliases ---
    EndpointV2 internal srcEndpoint;
    EndpointV2 internal dstEndpoint;
    ReceiveUln302 internal srcReceiveUln;
    ReceiveUln302 internal dstReceiveUln;
    SendUln302 internal srcSendUln;
    SendUln302 internal dstSendUln;
    DVN internal srcDvn;
    DVN internal dstDvn;

    uint32 internal constant SRC_EID = uint32(Constant.EID_ETHEREUM); // 101
    uint32 internal constant DST_EID = uint32(Constant.EID_BSC); // 102

    // --- Events ---
    event PacketVerified(Origin origin, address receiver, bytes32 payloadHash);
    event PayloadVerified(address dvn, bytes header, uint256 confirmations, bytes32 proofHash);
    event PacketDelivered(Origin origin, address receiver);

    function setUp() public virtual {
        // Deploy two full V2 stacks
        srcFixture = Setup.loadFixtureV2(SRC_EID);
        dstFixture = Setup.loadFixtureV2(DST_EID);

        // Wire them to each other
        Setup.wireFixtureV2WithRemote(srcFixture, DST_EID);
        Setup.wireFixtureV2WithRemote(dstFixture, SRC_EID);

        // Set convenience aliases
        srcEndpoint = srcFixture.endpointV2;
        dstEndpoint = dstFixture.endpointV2;
        srcReceiveUln = srcFixture.receiveUln302;
        dstReceiveUln = dstFixture.receiveUln302;
        srcSendUln = srcFixture.sendUln302;
        dstSendUln = dstFixture.sendUln302;
        srcDvn = srcFixture.dvn;
        dstDvn = dstFixture.dvn;
    }

    // ========================= Helpers =========================

    /// @dev Create a packet from src to dst
    function _makePacket(
        uint64 nonce,
        address sender,
        address receiver,
        bytes memory message
    ) internal pure returns (Packet memory) {
        return PacketUtil.newPacket(nonce, SRC_EID, sender, DST_EID, receiver, message);
    }

    /// @dev Encode a packet and split into header + payload
    function _encodeAndSplit(Packet memory packet)
        internal
        pure
        returns (bytes memory encoded, bytes memory header, bytes memory payload, bytes32 payloadHash)
    {
        encoded = PacketV1Codec.encode(packet);
        header = BytesLib.slice(encoded, 0, 81);
        payload = BytesLib.slice(encoded, 81, encoded.length - 81);
        payloadHash = keccak256(payload);
    }

    /// @dev Have the DVN verify a packet header + payloadHash on the dst receive ULN
    function _dvnVerify(
        DVN dvn,
        ReceiveUln302 receiveUln,
        bytes memory header,
        bytes32 payloadHash,
        uint64 confirmations
    ) internal {
        vm.prank(address(dvn));
        receiveUln.verify(header, payloadHash, confirmations);
    }

    /// @dev Commit verification on the dst receive ULN (triggers endpoint.verify)
    function _commitVerification(ReceiveUln302 receiveUln, bytes memory header, bytes32 payloadHash) internal {
        receiveUln.commitVerification(header, payloadHash);
    }

    /// @dev Full flow: DVN verify + commit verification
    function _verifyPacketOnDst(
        Packet memory packet
    ) internal returns (bytes memory header, bytes32 payloadHash) {
        (, header, , payloadHash) = _encodeAndSplit(packet);
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _commitVerification(dstReceiveUln, header, payloadHash);
    }

    /// @dev Make the test contract act as an OApp that allows path initialization
    function allowInitializePath(Origin calldata) external pure virtual returns (bool) {
        return true;
    }

    /// @dev Dummy lzReceive for when this contract is the receiver
    function lzReceive(
        Origin calldata,
        bytes32,
        bytes calldata,
        address,
        bytes calldata
    ) external payable virtual {}
}
