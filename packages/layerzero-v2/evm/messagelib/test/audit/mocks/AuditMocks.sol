// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { ILayerZeroReceiver } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroReceiver.sol";

/// @dev Simple ERC20 used to simulate cross-chain token transfers in audit PoCs.
contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1_000_000e18);
    }
}

/// @dev Simulates an OFT-style receiver that holds tokens and transfers them
///      to the recipient encoded in the cross-chain message.
///
/// Message format: abi.encode(address recipient, uint256 amount)
contract MockOFTReceiver is ILayerZeroReceiver {
    IERC20 public token;
    address public endpoint;

    constructor(address _endpoint, address _token) {
        endpoint = _endpoint;
        token = IERC20(_token);
    }

    function allowInitializePath(Origin calldata) external pure returns (bool) {
        return true;
    }

    function nextNonce(uint32, bytes32) external pure returns (uint64) {
        return 0;
    }

    /// @dev Decodes (recipient, amount) and transfers tokens. Reverts if caller is not the endpoint.
    function lzReceive(
        Origin calldata,
        bytes32,
        bytes calldata _message,
        address,
        bytes calldata
    ) external payable {
        require(msg.sender == endpoint, "MockOFTReceiver: only endpoint");
        (address recipient, uint256 amount) = abi.decode(_message, (address, uint256));
        token.transfer(recipient, amount);
    }
}
