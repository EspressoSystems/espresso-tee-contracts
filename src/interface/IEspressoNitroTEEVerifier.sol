// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEspressoNitroTEEVerifier {
    // We only support version 3 for now
    error InvalidHeaderVersion();
    // This error is thrown when the enclave report fails to parse
    error FailedToParseEnclaveReport();
    // This error is thrown when the mrEnclave don't match
    error InvalidEnclaveHash();
    // This error is thrown when the reportDataHash doesn't match the hash signed by the TEE
    error InvalidReportDataHash();
    // This error is thrown when the reportData is too short
    error ReportDataTooShort();
    // This error is thrown when the data length is invalid
    error InvalidDataLength();
    // This error is thrown when the signer address is invalid
    error InvalidSignerAddress();
    error AttestationTooOld();

    event EnclaveHashSet(bytes32 enclaveHash, bool valid);
    event SignerRegistered(address signer, bytes32 enclaveHash);
    event DeletedRegisteredSigner(address signer);

    function registeredSigners(address signer) external view returns (bool);
    function registeredEnclaveHash(bytes32 enclaveHash) external view returns (bool);

    function registerSigner(bytes calldata attestation, bytes calldata data) external;

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external;
    function deleteRegisteredSigners(address[] memory signers) external;
}
