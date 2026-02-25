// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Sha256} from "./Sha256.sol";

/// @title Sha256Deployed
/// @notice Drop-in replacement for the SHA-256 precompile (0x02).
/// @dev Deploy once, then staticcall with raw input bytes.
///      Returns raw 32 bytes — identical interface to the native precompile.
contract Sha256Deployed {
    fallback() external {
        bytes memory data = msg.data;
        bytes32 digest = Sha256.hash(data);
        assembly {
            mstore(0x00, digest)
            return(0x00, 0x20)
        }
    }
}
