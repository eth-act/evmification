// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Pairing} from "./Pairing.sol";

/// @title PairingDeployed
/// @notice Drop-in replacement for the BLS12-381 pairing precompile (0x0f).
/// @dev Deploy once, then staticcall with raw input. Returns 32 bytes.
contract PairingDeployed {
    fallback() external {
        bytes memory input = msg.data;
        bytes memory output = Pairing.pairing(input);
        assembly {
            return(add(output, 0x20), mload(output))
        }
    }
}
