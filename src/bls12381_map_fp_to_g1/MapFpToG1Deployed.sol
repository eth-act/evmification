// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {MapFpToG1} from "./MapFpToG1.sol";

/// @title MapFpToG1Deployed
/// @notice Drop-in replacement for the MAP_FP_TO_G1 precompile (0x10).
/// @dev Deploy once, then staticcall with raw 64-byte input.
///      Returns raw 128 bytes — identical interface to the native precompile.
contract MapFpToG1Deployed {
    fallback() external {
        bytes memory input = msg.data;
        bytes memory output = MapFpToG1.mapToG1(input);
        assembly {
            return(add(output, 0x20), mload(output))
        }
    }
}
