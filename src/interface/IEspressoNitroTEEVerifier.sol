// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEspressoNitroTEEVerifier {
    // This error is thrown when the PCR0 values don't match
    error InvalidAWSEnclaveHash();

    event AWSEnclaveHashSet(bytes32 enclaveHash, bool valid);
    event AWSSignerRegistered(address signer, bytes32 enclaveHash);
    event DeletedAWSRegisteredSigner(address signer);
    event AttestationDataSubmitted(address indexed signer, bytes attestation, bytes signature);

    function registeredSigners(address signer) external view returns (bool);
    function registeredEnclaveHash(bytes32 enclaveHash) external view returns (bool);

    function registerSigner(bytes calldata attestation, bytes calldata data) external;

    function verifyCACert(bytes calldata certificate, bytes32 parentCertHash) external;
    function verifyClientCert(bytes calldata certificate, bytes32 parentCertHash) external;
    function certVerified(bytes32 certHash) external view returns (bool);

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external;
    function deleteRegisteredSigners(address[] memory signers) external;
}
