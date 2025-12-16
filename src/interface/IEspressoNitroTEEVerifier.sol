// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    VerificationResult
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

interface IEspressoNitroTEEVerifier {
    // This error is thrown when the PCR0 values don't match
    error InvalidAWSEnclaveHash();
    // This error is thrown when the nonce has already been used
    error NonceAlreadyUsed();
    // This error is thrown when the ZK proof verification fails
    error VerificationFailed(VerificationResult result);

    event AWSEnclaveHashSet(bytes32 enclaveHash, bool valid);
    event AWSSignerRegistered(address signer, bytes32 enclaveHash);
    event DeletedAWSRegisteredSigner(address signer);

    function registeredSigners(address signer) external view returns (bool);
    function registeredEnclaveHash(bytes32 enclaveHash) external view returns (bool);

    function registerSigner(bytes calldata output, bytes calldata proofBytes) external;

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external;
    function deleteRegisteredSigners(address[] memory signers) external;
}
