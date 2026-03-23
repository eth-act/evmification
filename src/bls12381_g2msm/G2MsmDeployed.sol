// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {G2Msm} from "./G2Msm.sol";

/// @title G2MsmDeployed
/// @notice Drop-in replacement for the G2MSM precompile (0x0e).
/// @dev Deploy once, then staticcall with raw k*288-byte input.
///      Returns raw 256 bytes -- identical interface to the native precompile.
contract G2MsmDeployed {
    fallback() external {
        bytes memory input = msg.data;
        bytes memory output = G2Msm.g2Msm(input);
        assembly {
            return(add(output, 0x20), mload(output))
        }
    }
}
