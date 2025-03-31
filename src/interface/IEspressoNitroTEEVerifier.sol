// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEspressoNitroTEEVerifier {
    // This error is thrown when the PCR0 values don't match
    error InvalidEnclaveHash();

    event EnclaveHashSet(bytes32 enclaveHash, bool valid);
    event SignerRegistered(address signer, bytes32 enclaveHash);
    event DeletedRegisteredSigner(address signer);

    function registeredSigners(address signer) external view returns (bool);
    function registeredEnclaveHash(bytes32 enclaveHash) external view returns (bool);

    function registerSigner(bytes calldata attestation, bytes calldata data) external;

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external;
    function deleteRegisteredSigners(address[] memory signers) external;
}
