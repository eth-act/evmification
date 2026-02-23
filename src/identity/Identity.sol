// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Identity
/// @notice Pure Solidity replacement for the identity precompile (EIP-7666).
/// @dev Equivalent bytecode: CALLDATASIZE PUSH0 PUSH0 CALLDATACOPY CALLDATASIZE PUSH0 RETURN (0x365f5f37365ff3).
///      As a library, this simply copies the input bytes in memory.
library Identity {
    /// @notice Copies input data without the precompile.
    /// @param data The input data to copy.
    /// @return result An identical copy of the input.
    function identity(bytes memory data) internal pure returns (bytes memory result) {
        uint256 len = data.length;
        result = new bytes(len);
        assembly {
            let src := add(data, 0x20)
            let dst := add(result, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }
}
