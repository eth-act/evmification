// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IdentityDeployed
/// @notice Drop-in replacement for the identity precompile (0x04).
/// @dev Deploy once, then staticcall with raw input bytes.
///      Returns the same bytes — identical interface to the native precompile.
contract IdentityDeployed {
    fallback() external {
        assembly {
            calldatacopy(0x00, 0x00, calldatasize())
            return(0x00, calldatasize())
        }
    }
}
