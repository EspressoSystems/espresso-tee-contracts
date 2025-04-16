// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEspressoNitroTEEVerifier {
    // This error is thrown when the PCR0 values don't match
    error InvalidAWSEnclaveHash();

    event AWSEnclaveHashSet(bytes32 enclaveHash, bool valid);
    event AWSSignerRegistered(address signer, bytes32 enclaveHash);
    event DeletedAWSRegisteredSigner(address signer);

    function registeredSigners(address signer) external view returns (bool);
    function registeredEnclaveHash(bytes32 enclaveHash) external view returns (bool);

    function registerSigner(bytes calldata attestation, bytes calldata data) external;

    function verifyCert(bytes calldata certificate, bytes32 parentCertHash, bool isCA) external;
    function certVerified(bytes32 parentCertHash) external view returns (bytes memory);

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external;
    function deleteRegisteredSigners(address[] memory signers) external;
}
