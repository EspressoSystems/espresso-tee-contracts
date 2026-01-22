// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {ServiceType} from "./types/Types.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "./interface/ITEEHelper.sol";

/**
 * @title TEEHelper - FIXED VERSION
 * @notice Fixed unbounded loop DoS vulnerability in deleteEnclaveHashes
 * @dev Implements three-layer protection:
 *      1. Batched deletion to prevent gas exhaustion
 *      2. Maximum signers per hash limit
 *      3. Two-step deletion process for emergency response
 */
abstract contract TEEHelper is ITEEHelper, Ownable2Step {
    using EnumerableSet for EnumerableSet.AddressSet;
    
    /// @notice Maximum number of signers allowed per enclave hash to prevent DoS
    uint256 public constant MAX_SIGNERS_PER_HASH = 1000;
    
    /// @notice Maximum number of signers to delete in a single transaction
    uint256 public constant MAX_BATCH_DELETE_SIZE = 100;
    
    // Mappings
    mapping(ServiceType => mapping(bytes32 enclaveHash => bool valid)) public
        registeredEnclaveHashes;

    mapping(ServiceType => mapping(address signer => bool valid)) public registeredServices;
    mapping(ServiceType => mapping(bytes32 enclaveHash => EnumerableSet.AddressSet signers))
        internal enclaveHashToSigner;

    // Events for new functionality
    event EnclaveHashDisabled(bytes32 indexed enclaveHash, ServiceType indexed service);
    event SignerCountLimitReached(bytes32 indexed enclaveHash, ServiceType indexed service, uint256 count);

    constructor() Ownable2Step() {
        _transferOwnership(msg.sender);
    }

    /**
     * @notice This function allows the owner to set the enclave hash, setting valid to true will allow any enclave
     * with a valid pcr0 hash to register a signer (address which was generated inside the TEE). Setting valid to false
     * will further remove the enclave hash from the registered enclave hash list thus preventing any enclave with the given
     * hash from registering a signer.
     * @param enclaveHash The hash of the enclave
     * @param valid Whether the enclave hash is valid or not
     * @param service The service type (BatchPoster or CaffNode)
     */
    function setEnclaveHash(bytes32 enclaveHash, bool valid, ServiceType service)
        external
        virtual
        onlyOwner
    {
        registeredEnclaveHashes[service][enclaveHash] = valid;
        emit EnclaveHashSet(enclaveHash, valid, service);
    }

    /**
     * @notice This function retrieves whether a signer is registered or not
     * @param signer The address of the signer
     * @param service The service type (BatchPoster or CaffNode)
     * @return bool True if the signer is registered, false otherwise
     */
    function registeredService(address signer, ServiceType service)
        external
        view
        virtual
        returns (bool)
    {
        return registeredServices[service][signer];
    }

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     * @param enclaveHash The hash of the enclave
     * @param service The service type (BatchPoster or CaffNode)
     * @return bool True if the enclave hash is registered, false otherwise
     */
    function registeredEnclaveHash(bytes32 enclaveHash, ServiceType service)
        external
        view
        virtual
        returns (bool)
    {
        return registeredEnclaveHashes[service][enclaveHash];
    }

    /**
     * @notice This function retrieves the list of signers registered for a given enclave hash
     * @param enclaveHash The hash of the enclave
     * @param service The service type (BatchPoster or CaffNode)
     * @return address[] The list of signers registered for the given enclave hash
     */
    function enclaveHashSigners(bytes32 enclaveHash, ServiceType service)
        external
        view
        virtual
        returns (address[] memory)
    {
        EnumerableSet.AddressSet storage signersSet = enclaveHashToSigner[service][enclaveHash];
        return signersSet.values();
    }

    /**
     * @notice Returns the number of signers for a given enclave hash
     * @param enclaveHash The hash of the enclave
     * @param service The service type
     * @return uint256 The number of signers
     */
    function getSignerCount(bytes32 enclaveHash, ServiceType service)
        public
        view
        returns (uint256)
    {
        return enclaveHashToSigner[service][enclaveHash].length();
    }

    /**
     * @notice Internal function to check signer limit before registration
     * @dev Called by child contracts before adding a new signer
     * @param enclaveHash The hash of the enclave
     * @param service The service type
     */
    function _checkSignerLimit(bytes32 enclaveHash, ServiceType service) internal {
        uint256 currentCount = enclaveHashToSigner[service][enclaveHash].length();
        
        if (currentCount >= MAX_SIGNERS_PER_HASH) {
            emit SignerCountLimitReached(enclaveHash, service, currentCount);
            revert("Maximum signers for this enclave hash reached");
        }
    }

    /**
     * @notice FIX #1: Batch deletion of signers for an enclave hash
     * @dev Deletes up to maxIterations signers in a single transaction
     * @param enclaveHash The hash to clean up
     * @param service The service type
     * @param maxIterations Maximum number of signers to delete (0 = use default)
     * @return remaining Number of signers still remaining after this batch
     */
    function deleteEnclaveHashBatch(
        bytes32 enclaveHash,
        ServiceType service,
        uint256 maxIterations
    ) public onlyOwner returns (uint256 remaining) {
        // Use default if maxIterations is 0
        if (maxIterations == 0) {
            maxIterations = MAX_BATCH_DELETE_SIZE;
        }
        
        // Cap at safe maximum to prevent accidental gas exhaustion
        require(maxIterations <= MAX_BATCH_DELETE_SIZE, "Batch size too large");
        
        EnumerableSet.AddressSet storage signersSet = enclaveHashToSigner[service][enclaveHash];
        
        uint256 iterations = 0;
        while (signersSet.length() > 0 && iterations < maxIterations) {
            address signer = signersSet.at(0);
            delete registeredServices[service][signer];
            // slither-disable-next-line unused-return
            signersSet.remove(signer);
            emit DeletedRegisteredService(signer, service);
            iterations++;
        }
        
        remaining = signersSet.length();
        
        // Only delete the hash registration if all signers are removed
        if (remaining == 0) {
            delete registeredEnclaveHashes[service][enclaveHash];
            emit DeletedEnclaveHash(enclaveHash, service);
        }
        
        return remaining;
    }

    /**
     * @notice FIX #2: Two-step deletion - Immediately disable hash, then cleanup
     * @dev Disables new registrations immediately without needing to delete all signers
     * @param enclaveHash The hash to disable
     * @param service The service type
     */
    function disableEnclaveHash(bytes32 enclaveHash, ServiceType service)
        external
        onlyOwner
    {
        registeredEnclaveHashes[service][enclaveHash] = false;
        emit EnclaveHashDisabled(enclaveHash, service);
    }

    /**
     * @notice Clean up signers from a disabled enclave hash in batches
     * @dev Can be called multiple times until all signers are removed
     * @param enclaveHash The hash to clean up
     * @param service The service type
     * @param maxIterations Maximum number of signers to process
     * @return remaining Number of signers still remaining
     */
    function cleanupDisabledHashBatch(
        bytes32 enclaveHash,
        ServiceType service,
        uint256 maxIterations
    ) external onlyOwner returns (uint256 remaining) {
        require(
            !registeredEnclaveHashes[service][enclaveHash],
            "Hash must be disabled first via disableEnclaveHash()"
        );
        
        return deleteEnclaveHashBatch(enclaveHash, service, maxIterations);
    }

    /**
     * @notice MODIFIED: Original function now checks batch size limits
     * @dev This function now reverts if a hash has too many signers
     *      Use deleteEnclaveHashBatch() for hashes with many signers
     * @param enclaveHashes The list of enclave hashes to be deleted
     * @param service The service type (BatchPoster or CaffNode)
     */
    function deleteEnclaveHashes(bytes32[] memory enclaveHashes, ServiceType service)
        external
        virtual
        onlyOwner
    {
        for (uint256 i = 0; i < enclaveHashes.length; i++) {
            EnumerableSet.AddressSet storage signersSet =
                enclaveHashToSigner[service][enclaveHashes[i]];
            
            uint256 signerCount = signersSet.length();
            
            // Prevent unbounded loop DoS
            require(
                signerCount <= MAX_BATCH_DELETE_SIZE,
                "Too many signers. Use deleteEnclaveHashBatch() or disableEnclaveHash() first"
            );
            
            // Safe to delete in one transaction
            while (signersSet.length() > 0) {
                address signer = signersSet.at(0);
                delete registeredServices[service][signer];
                // slither-disable-next-line unused-return
                signersSet.remove(signer);
                emit DeletedRegisteredService(signer, service);
            }
            delete registeredEnclaveHashes[service][enclaveHashes[i]];
            emit DeletedEnclaveHash(enclaveHashes[i], service);
        }
    }

    /**
     * @notice Utility function to check if a hash can be safely deleted in one transaction
     * @param enclaveHash The hash to check
     * @param service The service type
     * @return canDelete True if safe to delete in one transaction
     * @return signerCount Number of signers that need to be deleted
     */
    function canDeleteInOneTransaction(bytes32 enclaveHash, ServiceType service)
        external
        view
        returns (bool canDelete, uint256 signerCount)
    {
        signerCount = enclaveHashToSigner[service][enclaveHash].length();
        canDelete = signerCount <= MAX_BATCH_DELETE_SIZE;
    }
}

