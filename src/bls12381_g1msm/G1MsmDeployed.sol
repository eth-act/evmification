// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {G1Msm} from "./G1Msm.sol";

/// @title G1MsmDeployed
/// @notice Drop-in replacement for the G1MSM precompile (0x0c).
/// @dev Deploy once, then staticcall with raw k*160-byte input.
///      Returns raw 128 bytes -- identical interface to the native precompile.
contract G1MsmDeployed {
    fallback() external {
        bytes memory input = msg.data;
        bytes memory output = G1Msm.g1Msm(input);
        assembly {
            return(add(output, 0x20), mload(output))
        }
    }
}
