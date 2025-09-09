// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Service} from "./IEspressoTEEVerifier.sol"
interface IEspressoNitroTEEVerifier {
    // This error is thrown when the PCR0 values don't match
    error InvalidAWSEnclaveHash();

    event AWSEnclaveHashSet(bytes32 enclaveHash, bool valid, Service service);
    event AWSServiceRegistered(address signer, bytes32 enclaveHash, Service service);
    event DeletedAWSRegisteredService(address signer, Service service);

    //This will serve to check if a Caff node is regsitered in the NitroTEEVerifier contract.
    function registeredCaffNode(address signer) external view returns (bool);

    function registeredBatchPoster(address signer) external view returns (bool);
    function registeredEnclaveHash(bytes32 enclaveHash) external view returns (bool);

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

    function setEnclaveHash(bytes32 enclaveHash, bool valid, ) external;
    /*
    * @notice This function is responsible for removing registered addresses from the list of valid Caff Nodes
    */
    function deleteRegisteredCaffNodes(address[] memory signers) external;
    /*
    * @notice This function is responsible for removing registered addresses from the list of valid Batch Posters
    */
    function deleteRegisteredBatchPosters(address[] memory signers) external;
}
