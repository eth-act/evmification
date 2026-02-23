// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IdentityPrecompile
/// @notice Wrapper around the EVM identity precompile (address 0x04).
library IdentityPrecompile {
    /// @notice Copies input data using the identity precompile.
    /// @param data The input data to copy.
    /// @return result An identical copy of the input.
    function identity(bytes memory data) internal view returns (bytes memory result) {
        uint256 len = data.length;
        result = new bytes(len);
        assembly {
            let success := staticcall(gas(), 0x04, add(data, 0x20), len, add(result, 0x20), len)
            if iszero(success) { revert(0, 0) }
        }
    }
}
