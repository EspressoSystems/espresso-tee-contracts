// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../types/Types.sol";

interface IEspressoNitroTEEVerifier {
    // This error is thrown when the PCR0 values don't match
    error InvalidAWSEnclaveHash(bytes32 pcr0Hash, ServiceType service);

    event AWSServiceEnclaveHashSet(bytes32 indexed enclaveHash, bool indexed valid, ServiceType indexed service);
    event AWSNitroServiceRegistered(address indexed signer, bytes32 indexed enclaveHash, ServiceType indexed service);
    event DeletedAWSRegisteredService(address indexed signer, ServiceType indexed service);

    /*
    * @notice This function is for checking the registration status of AWS Nitro TEE Caff Nodes and is a helper function for the EspressoTEEVerifier
    */
    function registeredCaffNodes(address signer) external view returns (bool);

    /*
    * @notice This function is for checking the registration status of AWS Nitro TEE Batch Posters and is a helper function for the EspressoTEEVerifier
    */
    function registeredBatchPosters(address signer) external view returns (bool);

    function registeredBatchPosterEnclaveHashes(bytes32 enclaveHash) external view returns (bool);

    function registeredCaffNodeEnclaveHashes(bytes32 enclaveHash) external view returns (bool);

    /*
    * @notice This function is for registering AWS Nitro TEE Caff Nodes and is a helper function for the EspressoTEEVerifier
    */
    function registerCaffNode(bytes calldata attestation, bytes calldata data) external;

    /*
    * @notice This function is for registering AWS Nitro Batch Posters and is a helper function for the EspressoTEEVerifier
    */
    function registerBatchPoster(bytes calldata verificationData, bytes calldata data) external;

    function verifyCACert(bytes calldata certificate, bytes32 parentCertHash) external;
    function verifyClientCert(bytes calldata certificate, bytes32 parentCertHash) external;
    function certVerified(bytes32 certHash) external view returns (bool);

    function setEnclaveHash(bytes32 enclaveHash, bool valid, ServiceType service) external;
    /*
    * @notice This function is responsible for removing registered addresses from the list of valid Caff Nodes
    */
    function deleteRegisteredCaffNodes(address[] memory signers) external;
    /*
    * @notice This function is responsible for removing registered addresses from the list of valid Batch Posters
    */
    function deleteRegisteredBatchPosters(address[] memory signers) external;
}
