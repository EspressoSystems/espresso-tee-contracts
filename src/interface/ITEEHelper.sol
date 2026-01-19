// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ServiceType} from "../types/Types.sol";

interface ITEEHelper {
    // Thrown when an unsupported service type is provided
    // function signature: 0x00bf4e89
    error UnsupportedServiceType();
    // Thrown when an invalid enclave hash is provided for a service type
    // function signature: 0x94f1e6f9
    error InvalidEnclaveHash(bytes32 enclaveHash, ServiceType service);
    // Thrown when an invalid signer address is provided
    // function signature: 0x4501a919
    error InvalidSignerAddress();

    // Emitted when an enclave hash is deleted
    event DeletedEnclaveHash(bytes32 indexed enclaveHash, ServiceType indexed service);

    // Emitted when a registered service is deleted
    event DeletedRegisteredService(address indexed signer, ServiceType indexed service);

    // Emitted when a service is registered
    event ServiceRegistered(
        address indexed signer, bytes32 indexed enclaveHash, ServiceType indexed service
    );

    // Emitted when an enclave hash is set
    event EnclaveHashSet(
        bytes32 indexed enclaveHash, bool indexed valid, ServiceType indexed service
    );

    /**
     * @notice This function allows the owner to set the enclave hash, setting valid to true will allow any enclave
     * with a valid pcr0 hash to register a signer (address which was generated inside the TEE). Setting valid to false
     * will further remove the enclave hash from the registered enclave hash list thus preventing any enclave with the given
     * hash from registering a signer.
     * @param enclaveHash The hash of the enclave
     * @param valid Whether the enclave hash is valid or not
     * @param service The service type (BatchPoster or CaffNode)
     */
    function setEnclaveHash(bytes32 enclaveHash, bool valid, ServiceType service) external;

    /*
     * @notice This function retrieves whether an enclave hash is registered or not
     * @param enclaveHash The hash of the enclave
     * @param service The service type (BatchPoster or CaffNode)
     * @return bool True if the enclave hash is registered, false otherwise
     */
    function registeredEnclaveHash(bytes32 enclaveHash, ServiceType service)
        external
        view
        returns (bool);

    /*
     * @notice This function retrieves whether a signer is registered or not
     * @param signer The address of the signer
     * @param service The service type (BatchPoster or CaffNode)
     * @return bool True if the signer is registered, false otherwise
     */
    function registeredService(address signer, ServiceType service) external view returns (bool);

    /*
     * @notice This function retrieves the list of signers registered for a given enclave hash
     * @param enclaveHash The hash of the enclave
     * @param service The service type (BatchPoster or CaffNode)
     * @return address[] The list of signers registered for the given enclave hash
     */
    function enclaveHashSigners(bytes32 enclaveHash, ServiceType service)
        external
        view
        returns (address[] memory);

    /*
     * @notice This function allows the owner to delete registered enclave hashes from the list of valid enclave hashes
     * @param enclaveHashes The array of enclave hashes to delete
     * @param service The service type (BatchPoster or CaffNode)
     */
    function deleteEnclaveHashes(bytes32[] memory enclaveHashes, ServiceType service) external;
}
