// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ServiceType} from "../types/Types.sol";

/**
 * @title EspressoNitroTEEVerifierMock
 * @notice Mock contract for AWS Nitro TEE verification. Skips all attestation verification
 *         but still requires signers to be registered before they can be used.
 */
contract EspressoNitroTEEVerifierMock {
    mapping(ServiceType => mapping(bytes32 => bool)) public registeredEnclaveHashes;
    mapping(ServiceType => mapping(address => bool)) public registeredServices;

    constructor() {
        // No enclave hash required for mock
    }

    /**
     * @notice Register a signer without verification. In mock, we skip ZK proof verification.
     * @param output The public output (ignored in mock, but we extract signer from it)
     * @param proofBytes The proof bytes (ignored in mock)
     */
    function registerService(bytes calldata output, bytes calldata proofBytes, ServiceType service)
        external
    {
        // In mock, we expect the signer address to be passed in the output parameter
        // as the first 20 bytes for simplicity
        require(output.length >= 20, "Output must contain signer address");

        address signer = address(uint160(bytes20(output[:20])));
        require(signer != address(0), "Invalid signer address");

        if (!registeredServices[service][signer]) {
            registeredServices[service][signer] = true;
        }
    }

    function registeredEnclaveHash(bytes32 enclaveHash, ServiceType service)
        external
        view
        returns (bool)
    {
        return registeredEnclaveHashes[service][enclaveHash];
    }

    function registeredService(address signer, ServiceType service) external view returns (bool) {
        return registeredServices[service][signer];
    }

    function setEnclaveHash(bytes32 enclaveHash, bool valid, ServiceType service) external {
        registeredEnclaveHashes[service][enclaveHash] = valid;
    }
}
