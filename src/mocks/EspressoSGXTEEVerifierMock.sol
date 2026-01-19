// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEspressoSGXTEEVerifier} from "../interface/IEspressoSGXTEEVerifier.sol";
import {Header} from "@automata-network/dcap-attestation/contracts/types/CommonStruct.sol";
import {EnclaveReport} from "@automata-network/dcap-attestation/contracts/types/V3Structs.sol";

/**
 * @title EspressoSGXTEEVerifierMock
 * @notice Mock contract for SGX TEE verification. Skips all quote verification
 *         but still requires signers to be registered before they can be used.
 */
contract EspressoSGXTEEVerifierMock is IEspressoSGXTEEVerifier {
    mapping(bytes32 => bool) public registeredEnclaveHash;
    mapping(address => bool) public registeredSigners;

    constructor() {
        // No enclave hash or quote verifier required for mock
    }

    /**
     * @notice Verify function - in mock, always returns an empty EnclaveReport
     * @param rawQuote The raw quote (ignored in mock)
     * @param reportDataHash The report data hash (ignored in mock)
     */
    function verify(bytes calldata rawQuote, bytes32 reportDataHash)
        external
        view
        returns (EnclaveReport memory)
    {
        // Return empty enclave report in mock
        return EnclaveReport({
            cpuSvn: bytes16(0),
            miscSelect: bytes4(0),
            reserved1: bytes28(0),
            attributes: bytes16(0),
            mrEnclave: bytes32(0),
            reserved2: bytes32(0),
            mrSigner: bytes32(0),
            reserved3: new bytes(96),
            isvProdId: 0,
            isvSvn: 0,
            reserved4: new bytes(60),
            reportData: new bytes(64)
        });
    }

    /**
     * @notice Register a signer without verification. In mock, we skip quote verification.
     * @param attestation The attestation (ignored in mock)
     * @param data The signer address as bytes (20 bytes)
     */
    function registerSigner(bytes calldata attestation, bytes calldata data) external {
        require(data.length == 20, "Invalid data length");

        address signer = address(uint160(bytes20(data[:20])));
        require(signer != address(0), "Invalid signer address");

        if (!registeredSigners[signer]) {
            registeredSigners[signer] = true;
            emit SignerRegistered(signer, bytes32(0));
        }
    }

    function parseQuoteHeader(bytes calldata rawQuote)
        external
        pure
        returns (Header memory header)
    {
        // Return empty header in mock
        return header;
    }

    function parseEnclaveReport(bytes memory rawEnclaveReport)
        external
        pure
        returns (bool success, EnclaveReport memory enclaveReport)
    {
        // Always succeed with empty report in mock
        return (true, enclaveReport);
    }

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external {
        registeredEnclaveHash[enclaveHash] = valid;
        emit EnclaveHashSet(enclaveHash, valid);
    }

    function deleteRegisteredSigners(address[] memory signers) external {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredSigners[signers[i]];
            emit DeletedRegisteredSigner(signers[i]);
        }
    }

    function setQuoteVerifier(address quoteVerifierAddress) external {
        // No-op in mock
        emit QuoteVerifierSet(quoteVerifierAddress);
    }
}
