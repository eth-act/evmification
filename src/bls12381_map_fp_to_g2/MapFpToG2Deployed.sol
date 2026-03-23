// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {MapFpToG2} from "./MapFpToG2.sol";

/// @title MapFpToG2Deployed
/// @notice Drop-in replacement for the MAP_FP_TO_G2 precompile (0x11).
/// @dev Deploy once, then staticcall with raw 128-byte input.
///      Returns raw 256 bytes — identical interface to the native precompile.
contract MapFpToG2Deployed {
    fallback() external {
        bytes memory input = msg.data;
        bytes memory output = MapFpToG2.mapToG2(input);
        assembly {
            return(add(output, 0x20), mload(output))
        }
    }
}
