// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {G2Add} from "./G2Add.sol";

/// @title G2AddDeployed
/// @notice Drop-in replacement for the G2ADD precompile (0x0d).
/// @dev Deploy once, then staticcall with raw 512-byte input.
///      Returns raw 256 bytes -- identical interface to the native precompile.
contract G2AddDeployed {
    fallback() external {
        bytes memory input = msg.data;
        bytes memory output = G2Add.g2Add(input);
        assembly {
            return(add(output, 0x20), mload(output))
        }
    }
}
