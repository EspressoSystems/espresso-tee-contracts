// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEspressoNitroTEEVerifier} from "../interface/IEspressoNitroTEEVerifier.sol";
import {
    VerificationResult
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title EspressoNitroTEEVerifierMock
 * @notice Mock contract for AWS Nitro TEE verification. Skips all attestation verification
 *         but still requires signers to be registered before they can be used.
 */
contract EspressoNitroTEEVerifierMock is IEspressoNitroTEEVerifier {
    mapping(bytes32 => bool) public registeredEnclaveHash;
    mapping(address => bool) public registeredSigners;

    constructor() {
        // No enclave hash required for mock
    }

    /**
     * @notice Register a signer without verification. In mock, we skip ZK proof verification.
     * @param output The public output (ignored in mock, but we extract signer from it)
     * @param proofBytes The proof bytes (ignored in mock)
     */
    function registerSigner(bytes calldata output, bytes calldata proofBytes) external {
        // In mock, we expect the signer address to be passed in the output parameter
        // as the first 20 bytes for simplicity
        require(output.length >= 20, "Output must contain signer address");

        address signer = address(uint160(bytes20(output[:20])));
        require(signer != address(0), "Invalid signer address");

        if (!registeredSigners[signer]) {
            registeredSigners[signer] = true;
            emit AWSSignerRegistered(signer, bytes32(0));
        }
    }

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external {
        registeredEnclaveHash[enclaveHash] = valid;
        emit AWSEnclaveHashSet(enclaveHash, valid);
    }

    function deleteRegisteredSigners(address[] memory signers) external {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredSigners[signers[i]];
            emit DeletedAWSRegisteredSigner(signers[i]);
        }
    }

    function setNitroEnclaveVerifier(address nitroEnclaveVerifier) external {
        // No-op in mock
        emit NitroEnclaveVerifierSet(nitroEnclaveVerifier);
    }
}
