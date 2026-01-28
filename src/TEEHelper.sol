// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ServiceType} from "./types/Types.sol";
import "./interface/ITEEHelper.sol";

abstract contract TEEHelper is ITEEHelper, Initializable {
    struct TEEHelperStorage {
        mapping(ServiceType => mapping(bytes32 enclaveHash => bool valid)) registeredEnclaveHashes;
        mapping(ServiceType => mapping(address signer => bool valid)) registeredServices;
        address teeVerifier;
        // Track which enclave hash each signer was registered with (for automatic revocation)
        mapping(ServiceType => mapping(address signer => bytes32 enclaveHash)) signerToEnclaveHash;
    }

    // keccak256(abi.encode(uint256(keccak256("espresso.storage.TEEHelper")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant TEE_HELPER_STORAGE_SLOT =
        0x6c53fdf1cef7bc567e8d46761d9c42d29c5fad7063be8d47b686412bfc375800;

    function _layout() internal pure returns (TEEHelperStorage storage l) {
        bytes32 slot = TEE_HELPER_STORAGE_SLOT;
        assembly {
            l.slot := slot
        }
    }

    modifier onlyTEEVerifier() {
        if (msg.sender != teeVerifier()) {
            revert UnauthorizedTEEVerifier(msg.sender);
        }
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function __TEEHelper_init(address teeVerifier_) internal onlyInitializing {
        _setTEEVerifier(teeVerifier_);
    }

    function teeVerifier() public view returns (address) {
        return _layout().teeVerifier;
    }

    /**
     * @notice Allows the tee verifier to set the enclave hash, setting valid to true will allow any enclave
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
        onlyTEEVerifier
    {
        _layout().registeredEnclaveHashes[service][enclaveHash] = valid;
        emit EnclaveHashSet(enclaveHash, valid, service);
    }

    /**
     * @notice Validates if a signer is registered AND its enclave hash is still valid
     * @param signer The address of the signer
     * @param service The service type (BatchPoster or CaffNode)
     * @return bool True if signer is registered AND its enclave hash is still approved
     */
    function isSignerValid(address signer, ServiceType service)
        external
        view
        virtual
        returns (bool)
    {
        TEEHelperStorage storage $ = _layout();

        // Check if signer is registered
        if (!$.registeredServices[service][signer]) {
            return false;
        }

        // Check if signer's enclave hash is still approved
        bytes32 signerHash = $.signerToEnclaveHash[service][signer];

        // If no hash recorded (shouldn't happen with new registrations), be safe and reject
        if (signerHash == bytes32(0)) {
            return false;
        }

        // Check if the hash is still valid
        return $.registeredEnclaveHashes[service][signerHash];
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
        return _layout().registeredEnclaveHashes[service][enclaveHash];
    }

    /**
     * @notice Allows the tee verifier to delete registered enclave hashes from the list of valid enclave hashes
     * @dev FIX: Removes unbounded loop to prevent DoS attack
     * @dev NOTE: This only removes the hash authorization, existing signers remain in registeredServices
     * @dev To fully revoke signers, use isSignerValid() which checks hash validity
     * @param enclaveHashes The list of enclave hashes to be deleted
     * @param service The service type (BatchPoster or CaffNode)
     */
    function deleteEnclaveHashes(bytes32[] memory enclaveHashes, ServiceType service)
        external
        virtual
        onlyTEEVerifier
    {
        TEEHelperStorage storage $ = _layout();
        for (uint256 i = 0; i < enclaveHashes.length; i++) {
            bytes32 enclaveHash = enclaveHashes[i];

            // Verify the hash exists before deleting
            require($.registeredEnclaveHashes[service][enclaveHash], "Enclave hash not registered");

            // Delete the hash authorization (prevents NEW registrations)
            delete $.registeredEnclaveHashes[service][enclaveHash];
            emit DeletedEnclaveHash(enclaveHash, service);

            // NOTE: Existing signers are NOT automatically revoked from registeredServices
            // They remain in the mapping to avoid unbounded loop DoS
            // Use isSignerValid() for verification - it checks if hash is still valid
        }
    }

    function _setTEEVerifier(address newTEEVerifier) internal {
        if (newTEEVerifier == address(0)) {
            revert InvalidTEEVerifierAddress();
        }
        _layout().teeVerifier = newTEEVerifier;
        emit TeeVerifierSet(newTEEVerifier);
    }
}
