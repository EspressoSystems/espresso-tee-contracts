// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {ServiceType, UnsupportedServiceType} from "./types/Types.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";

import {
    EnumerableSet
} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "./interface/ITEEHelper.sol";

abstract contract TEEHelper is ITEEHelper, Ownable2Step {
    using EnumerableSet for EnumerableSet.AddressSet;
    // Mappings
    mapping(ServiceType => mapping(bytes32 enclaveHash => bool valid))
        public registeredEnclaveHashes;

    mapping(ServiceType => mapping(address signer => bool valid))
        public registeredSigners;
    mapping(ServiceType => mapping(bytes32 enclaveHash => EnumerableSet.AddressSet signers)) enclaveHashToSigner;

    // Checks if the service type is supported
    modifier onlySupportedServiceType(ServiceType service) {
        if (uint8(service) > uint8(ServiceType.CaffNode)) {
            revert UnsupportedServiceType();
        }
        _;
    }

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
    function setEnclaveHash(
        bytes32 enclaveHash,
        bool valid,
        ServiceType service
    ) external onlyOwner onlySupportedServiceType(service) {
        registeredEnclaveHashes[service][enclaveHash] = valid;
        emit EnclaveHashSet(enclaveHash, valid, service);
    }

    /**
     * @notice This function retrieves whether a signer is registered or not
     * @param signer The address of the signer
     * @param service The service type (BatchPoster or CaffNode)
     * @return bool True if the signer is registered, false otherwise
     */
    function registeredSigner(
        address signer,
        ServiceType service
    ) external view onlySupportedServiceType(service) returns (bool) {
        return registeredSigners[service][signer];
    }

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     * @param enclaveHash The hash of the enclave
     * @param service The service type (BatchPoster or CaffNode)
     * @return bool True if the enclave hash is registered, false otherwise
     */
    function registeredEnclaveHash(
        bytes32 enclaveHash,
        ServiceType service
    ) external view onlySupportedServiceType(service) returns (bool) {
        return registeredEnclaveHashes[service][enclaveHash];
    }

    /**
     * @notice This function retrieves the list of signers registered for a given enclave hash
     * @param enclaveHash The hash of the enclave
     * @param service The service type (BatchPoster or CaffNode)
     * @return address[] The list of signers registered for the given enclave hash
     */
    function enclaveHashSigners(
        bytes32 enclaveHash,
        ServiceType service
    )
        external
        view
        onlySupportedServiceType(service)
        returns (address[] memory)
    {
        EnumerableSet.AddressSet storage signersSet = enclaveHashToSigner[
            service
        ][enclaveHash];
        address[] memory signers = new address[](signersSet.length());
        for (uint256 i = 0; i < signersSet.length(); i++) {
            signers[i] = signersSet.at(i);
        }
        return signers;
    }

    /**
     * @notice This function allows the owner to delete registered enclave hashes from the list of valid enclave hashes
     * @param enclaveHashes The list of enclave hashes to be deleted
     * @param service The service type (BatchPoster or CaffNode)
     */
    function deleteEnclaveHashes(
        bytes32[] memory enclaveHashes,
        ServiceType service
    ) external onlyOwner onlySupportedServiceType(service) {
        for (uint256 i = 0; i < enclaveHashes.length; i++) {
            // also delete all the corresponding signers from registeredService mapping
            EnumerableSet.AddressSet storage signersSet = enclaveHashToSigner[
                service
            ][enclaveHashes[i]];
            while (signersSet.length() > 0) {
                address signer = signersSet.at(0);
                delete registeredSigners[service][signer];
                signersSet.remove(signer);
                emit DeletedRegisteredService(signer, service);
            }
            delete registeredEnclaveHashes[service][enclaveHashes[i]];
            emit DeletedEnclaveHash(enclaveHashes[i], service);
        }
    }
}
