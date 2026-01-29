// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ServiceType} from "../types/Types.sol";
import {VerifierJournal} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

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
        VerifierJournal memory journal = abi.decode(output, (VerifierJournal));

        // The publicKey's first byte 0x04 byte followed which only determine if the public key is compressed or not.
        // so we ignore the first byte.
        bytes memory publicKeyWithoutPrefix = new bytes(journal.publicKey.length - 1);
        for (uint256 i = 1; i < journal.publicKey.length; i++) {
            publicKeyWithoutPrefix[i - 1] = journal.publicKey[i];
        }

        bytes32 publicKeyHash = keccak256(publicKeyWithoutPrefix);
        // Note: We take the keccak hash first to derive the address.
        // This is the same which the go ethereum crypto library is doing for PubkeyToAddress()
        address signer = address(uint160(uint256(publicKeyHash)));
        // Mark the signer as registered
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

    function isSignerValid(address signer, ServiceType service) external view returns (bool) {
        return registeredServices[service][signer];
    }

    function setEnclaveHash(bytes32 enclaveHash, bool valid, ServiceType service) external {
        registeredEnclaveHashes[service][enclaveHash] = valid;
    }
}
