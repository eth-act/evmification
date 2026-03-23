// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {G1Add} from "./G1Add.sol";

/// @title G1AddDeployed
/// @notice Drop-in replacement for the G1ADD precompile (0x0b).
/// @dev Deploy once, then staticcall with raw 256-byte input.
///      Returns raw 128 bytes — identical interface to the native precompile.
contract G1AddDeployed {
    fallback() external {
        bytes memory input = msg.data;
        bytes memory output = G1Add.g1Add(input);
        assembly {
            return(add(output, 0x20), mload(output))
        }
    }
}
