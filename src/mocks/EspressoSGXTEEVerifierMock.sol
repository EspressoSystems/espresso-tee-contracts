// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEspressoSGXTEEVerifier} from "../interface/IEspressoSGXTEEVerifier.sol";

import {ServiceType} from "../types/Types.sol";

/**
 * @title EspressoSGXTEEVerifierMock
 * @notice Mock contract for SGX TEE verification. Skips all quote verification
 *         but still requires signers to be registered before they can be used.
 */
contract EspressoSGXTEEVerifierMock {
    mapping(ServiceType => mapping(bytes32 => bool)) public registeredEnclaveHashes;
    mapping(ServiceType => mapping(address => bool)) public registeredServices;

    constructor() {
        // No enclave hash or quote verifier required for mock
    }

    /**
     * @notice Register a signer without verification. In mock, we skip quote verification.
     * @param attestation The attestation (ignored in mock)
     * @param data The signer address as bytes (20 bytes)
     */
    function registerService(bytes calldata attestation, bytes calldata data, ServiceType service)
        external
    {
        require(data.length == 20, "Invalid data length");

        address signer = address(uint160(bytes20(data[:20])));
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
