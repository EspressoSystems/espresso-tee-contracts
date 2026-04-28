// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interface/ITEEHelper.sol";

abstract contract TEEHelper is ITEEHelper {
    mapping(bytes32 enclaveHash => bool valid) internal _registeredEnclaveHashes;
    mapping(address signer => bool valid) internal _registeredServices;
    address internal _teeVerifier;
    mapping(address signer => bytes32 enclaveHash) internal _signerToEnclaveHash;

    modifier onlyTEEVerifier() {
        if (msg.sender != teeVerifier()) {
            revert UnauthorizedTEEVerifier(msg.sender);
        }
        _;
    }

    constructor(address teeVerifier_) {
        _setTEEVerifier(teeVerifier_);
    }

    function teeVerifier() public view returns (address) {
        return _teeVerifier;
    }

    /**
     * @notice Allows the tee verifier to set the enclave hash, setting valid to true will allow any enclave
     * with a valid pcr0 hash to register a signer (address which was generated inside the TEE). Setting valid to false
     * will further remove the enclave hash from the registered enclave hash list thus preventing any enclave with the given
     * hash from registering a signer.
     * @param enclaveHash The hash of the enclave
     * @param valid Whether the enclave hash is valid or not
     */
    function setEnclaveHash(bytes32 enclaveHash, bool valid) external virtual onlyTEEVerifier {
        _registeredEnclaveHashes[enclaveHash] = valid;
        emit EnclaveHashSet(enclaveHash, valid);
    }

    /**
     * @notice Validates if a signer is registered AND its enclave hash is still valid
     * @param signer The address of the signer
     * @return bool True if signer is registered AND its enclave hash is still approved
     */
    function isSignerValid(address signer) external view virtual returns (bool) {
        // Check if signer is registered
        if (!_registeredServices[signer]) {
            return false;
        }

        // Check if signer's enclave hash is still approved
        bytes32 signerHash = _signerToEnclaveHash[signer];

        // If no hash recorded (shouldn't happen with new registrations), be safe and reject
        if (signerHash == bytes32(0)) {
            return false;
        }

        // Check if the hash is still valid
        return _registeredEnclaveHashes[signerHash];
    }

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     * @param enclaveHash The hash of the enclave
     * @return bool True if the enclave hash is registered, false otherwise
     */
    function registeredEnclaveHash(bytes32 enclaveHash) external view virtual returns (bool) {
        return _registeredEnclaveHashes[enclaveHash];
    }

    /**
     * @notice Allows the tee verifier to delete registered enclave hashes from the list of valid enclave hashes
     * @dev FIX: Removes unbounded loop to prevent DoS attack
     * @dev NOTE: This only removes the hash authorization, existing signers remain in registeredServices
     * @dev To fully revoke signers, use isSignerValid() which checks hash validity
     * @param enclaveHashes The list of enclave hashes to be deleted
     */
    function deleteEnclaveHashes(bytes32[] memory enclaveHashes) external virtual onlyTEEVerifier {
        for (uint256 i = 0; i < enclaveHashes.length; i++) {
            bytes32 enclaveHash = enclaveHashes[i];

            // Skip already-unregistered hashes to keep batch deletion idempotent.
            if (!_registeredEnclaveHashes[enclaveHash]) {
                continue;
            }

            // Delete the hash authorization (prevents NEW registrations)
            delete _registeredEnclaveHashes[enclaveHash];
            emit DeletedEnclaveHash(enclaveHash);

            // NOTE: Existing signers are NOT automatically revoked from registeredServices
            // They remain in the mapping to avoid unbounded loop DoS
            // Use isSignerValid() for verification - it checks if hash is still valid
        }
    }

    /**
     * @notice Updates the authorized TEE verifier address.
     * @param newTEEVerifier The new verifier address allowed to manage enclave hashes.
     */
    function _setTEEVerifier(address newTEEVerifier) internal {
        if (newTEEVerifier == address(0)) {
            revert InvalidTEEVerifierAddress();
        }
        _teeVerifier = newTEEVerifier;
        emit TeeVerifierSet(newTEEVerifier);
    }
}
