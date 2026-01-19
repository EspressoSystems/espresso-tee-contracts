// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// Enum types for use in the TEEVerifier contracts.

/**
 * @notice Enum for representing services that can be registered via the EspressoTEEVerifier contract
 */
enum ServiceType {
    BatchPoster,
    CaffNode
}
