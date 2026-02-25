// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PointEval} from "./PointEval.sol";

/// @title PointEvalDeployed
/// @notice Drop-in replacement for the EIP-4844 point evaluation precompile (0x0a).
/// @dev Deploy once, then staticcall with raw 192-byte input.
///      Returns raw 64 bytes (two uint256s) — identical interface to the native precompile.
contract PointEvalDeployed {
    fallback() external {
        bytes memory input = msg.data;
        (uint256 fieldElementsPerBlob, uint256 blsModulus) = PointEval.verify(input);
        assembly {
            mstore(0x00, fieldElementsPerBlob)
            mstore(0x20, blsModulus)
            return(0x00, 0x40)
        }
    }
}
