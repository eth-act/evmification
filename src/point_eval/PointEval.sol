// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BLS12381} from "./BLS12381.sol";

/// @title PointEval
/// @notice KZG point evaluation (EIP-4844) implemented via BLS12-381 precompiles (EIP-2537).
/// @dev Verification equation: e(proof, [τ]₂ − z·G₂) · e(y·G₁ − commitment, G₂) = 1
library PointEval {
    uint256 constant FIELD_ELEMENTS_PER_BLOB = 4096;

    /// @notice G1 generator in EIP-2537 format (128 bytes).
    bytes constant G1_GEN =
        hex"00000000000000000000000000000000" hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"00000000000000000000000000000000" hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    /// @notice Verifies a KZG proof using BLS12-381 precompiles.
    /// @param input 192-byte input: versioned_hash (32) || z (32) || y (32) || commitment (48) || proof (48).
    /// @return fieldElementsPerBlob Always 4096.
    /// @return blsModulus The BLS12-381 scalar field modulus.
    function verify(bytes memory input) internal view returns (uint256 fieldElementsPerBlob, uint256 blsModulus) {
        require(input.length == 192, "invalid input length");

        // 1. Parse input
        bytes32 versionedHash;
        uint256 z;
        uint256 y;
        assembly {
            let ptr := add(input, 0x20)
            versionedHash := mload(ptr)
            z := mload(add(ptr, 0x20))
            y := mload(add(ptr, 0x40))
        }

        bytes memory commitment = new bytes(48);
        bytes memory proof = new bytes(48);
        assembly {
            let ptr := add(input, 0x20)
            // commitment at offset 96
            let cSrc := add(ptr, 0x60)
            let cDst := add(commitment, 0x20)
            mstore(cDst, mload(cSrc))
            mstore(add(cDst, 0x20), mload(add(cSrc, 0x20)))
            // proof at offset 144
            let pSrc := add(ptr, 0x90)
            let pDst := add(proof, 0x20)
            mstore(pDst, mload(pSrc))
            mstore(add(pDst, 0x20), mload(add(pSrc, 0x20)))
        }

        // 2. Validate versioned_hash: sha256(commitment) with byte 0 replaced by 0x01
        bytes32 commitHash = sha256(commitment);
        bytes32 expectedHash;
        assembly { expectedHash := or(and(commitHash, not(shl(248, 0xff))), shl(248, 0x01)) }
        require(versionedHash == expectedHash, "bad versioned hash");

        // 3. Validate z, y < BLS_MODULUS
        require(z < BLS12381.BLS_MODULUS, "z out of range");
        require(y < BLS12381.BLS_MODULUS, "y out of range");

        // 4. Decompress commitment and proof (48 → 128 bytes each)
        bytes memory commitPoint = BLS12381.decompressG1(commitment);
        bytes memory proofPoint = BLS12381.decompressG1(proof);

        // 5. KZG pairing check
        // 5a. y·G₁
        bytes memory yG1 = BLS12381.g1Mul(G1_GEN, bytes32(y));

        // 5b. y·G₁ − commitment (negate commitment, then add)
        bytes memory negCommit = BLS12381.negateG1(commitPoint);
        bytes memory lhsG1 = BLS12381.g1Add(yG1, negCommit);

        // 5c. z·G₂
        bytes memory zG2 = BLS12381.g2Mul(BLS12381.G2_GEN, bytes32(z));

        // 5d. [τ]₂ − z·G₂ (negate z·G₂, then add to TAU_G2)
        bytes memory negZG2 = BLS12381.negateG2(zG2);
        bytes memory rhsG2 = BLS12381.g2Add(BLS12381.TAU_G2, negZG2);

        // 5e. Pairing check: e(proof, [τ]₂ − z·G₂) · e(y·G₁ − commitment, G₂) = 1
        bytes memory pairs = abi.encodePacked(
            proofPoint,  // G1 (128 bytes)
            rhsG2,       // G2 (256 bytes)
            lhsG1,       // G1 (128 bytes)
            BLS12381.G2_GEN  // G2 (256 bytes)
        );
        require(BLS12381.pairing(pairs), "pairing check failed");

        return (FIELD_ELEMENTS_PER_BLOB, BLS12381.BLS_MODULUS);
    }
}
