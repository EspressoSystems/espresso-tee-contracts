// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {VerifierJournal} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title JournalValidation
 * @notice Library for validating Nitro Enclave ZK proof journals
 * @dev Extracted as a library to be reusable across contracts and tests
 */
library JournalValidation {
    /**
     * @notice Validates the VerifierJournal format and integrity
     * @dev Implements defense-in-depth by validating critical fields even if ZK circuit validates them
     * @param journal The journal returned from ZK proof verification
     *
     * Security validations:
     * 1. PCR array bounds - Ensures we can safely access journal.pcrs[0]
     * 2. PCR index correctness - Ensures pcrs[0] is actually PCR0 (code measurement), not PCR3 or other
     * 3. Public key length - Ensures 65-byte format (prevents predictable address attacks)
     * 4. Public key format - Ensures uncompressed format (0x04 prefix)
     *
     * Why validate even if ZK circuit should validate:
     * - Defense in depth: Multiple security layers
     * - Protection against ZK circuit bugs or gaps
     * - Explicit documentation of security requirements
     * - Minimal gas cost (~500 gas) for critical protection
     */
    function validateJournal(VerifierJournal memory journal) internal pure {
        // 1. Validate PCR array is not empty (prevents out-of-bounds on journal.pcrs[0])
        require(journal.pcrs.length > 0, "PCR array cannot be empty");

        // 2. CRITICAL: Validate PCR index is 0 (prevents validating wrong PCR!)
        // Without this check, an attacker could put PCR3 in position 0
        // Contract would validate PCR3 (benign) while PCR0 (code) is compromised
        require(journal.pcrs[0].index == 0, "First PCR must be PCR0 (code measurement)");

        // 3. CRITICAL: Validate public key length (prevents predictable address attacks)
        // Malformed keys (e.g., length=1) would hash to predictable addresses
        // Anyone could compute these addresses without needing a TEE
        require(journal.publicKey.length == 65, "Invalid public key length - must be 65 bytes");

        // 4. CRITICAL: Validate public key format (ensures correct address derivation)
        // Must be uncompressed ECDSA format: 0x04 + 32-byte X + 32-byte Y
        // Other formats would derive incorrect addresses
        require(journal.publicKey[0] == 0x04, "Public key must be uncompressed (0x04 prefix)");
    }
}

