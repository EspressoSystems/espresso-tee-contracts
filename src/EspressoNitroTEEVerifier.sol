// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {NitroValidator} from "@nitro-validator/NitroValidator.sol";
import {LibBytes} from "@nitro-validator/LibBytes.sol";
import {
    LibCborElement,
    CborElement,
    CborDecode
} from "@nitro-validator/CborDecode.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {
    IEspressoNitroTEEVerifier
} from "./interface/IEspressoNitroTEEVerifier.sol";
import {
    INitroEnclaveVerifier,
    VerifierJournal,
    ZkCoProcessorType
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
/**
 * @title  Verifies quotes from the AWS Nitro Enclave (TEE) and attests on-chain
 * @notice Contains the logic to verify an attestation and signature from the TEE and attest on-chain. It uses the NitroValidator contract
 *         from `base` to verify the quote. Along with some additional verification logic.
 *         (https://github.com/base/nitro-validator)
 * The code of this contract is inspired from SystemConfigGlobal.sol
 * (https://github.com/base/op-enclave/blob/main/contracts/src/SystemConfigGlobal.sol)
 */
contract EspressoNitroTEEVerifier is IEspressoNitroTEEVerifier, Ownable2Step {
    using CborDecode for bytes;
    using LibBytes for bytes;
    using LibCborElement for CborElement;

    // PCR0 keccak hash
    mapping(bytes32 => bool) public registeredEnclaveHash;
    // Registered signers
    mapping(address => bool) public registeredSigners;
    // Nitro Enclave Verifier
    INitroEnclaveVerifier public _nitroEnclaveVerifier;

    constructor(
        bytes32 enclaveHash,
        INitroEnclaveVerifier nitroEnclaveVerifier
    ) Ownable2Step() {
        _nitroEnclaveVerifier = nitroEnclaveVerifier;
        registeredEnclaveHash[enclaveHash] = true;
        _transferOwnership(msg.sender);
    }

    /**
     * @notice This function registers a new signer by verifying an attestation from the AWS Nitro Enclave (TEE)
     * @param output The output from the AWS Nitro Enclave (TEE)
     * @param proofBytes The cryptographic proof bytes over attestation
     */
    function registerSigner(
        bytes calldata output,
        bytes calldata proofBytes
    ) external {
        VerifierJournal memory journal = _nitroEnclaveVerifier.verify(
            output,
            // Currently only Succinct ZK coprocessor is supported
            ZkCoProcessorType.Succinct,
            proofBytes
        );
        // Hash the PCR0 value (combining first 32 bytes and last 16 bytes)
        bytes32 pcr0Hash = keccak256(
            abi.encodePacked(
                journal.pcrs[0].value.first,
                journal.pcrs[0].value.second
            )
        );
        if (!registeredEnclaveHash[pcr0Hash]) {
            revert InvalidAWSEnclaveHash();
        }

        // The publicKey's first byte 0x04 byte followed which only determine if the public key is compressed or not.
        // so we ignore the first byte.
        bytes memory publicKeyWithoutPrefix = new bytes(
            journal.publicKey.length - 1
        );
        for (uint256 i = 1; i < journal.publicKey.length; i++) {
            publicKeyWithoutPrefix[i - 1] = journal.publicKey[i];
        }
        bytes32 publicKeyHash = keccak256(publicKeyWithoutPrefix);
        // Note: We take the keccak hash first to derive the address.
        // This is the same which the go ethereum crypto library is doing for PubkeyToAddress()
        address enclaveAddress = address(uint160(uint256(publicKeyHash)));
        // Mark the signer as registered
        if (!registeredSigners[enclaveAddress]) {
            registeredSigners[enclaveAddress] = true;
            emit AWSSignerRegistered(enclaveAddress, pcr0Hash);
        }
    }

    function setEnclaveHash(
        bytes32 enclaveHash,
        bool valid
    ) external onlyOwner {
        registeredEnclaveHash[enclaveHash] = valid;
        emit AWSEnclaveHashSet(enclaveHash, valid);
    }

    function deleteRegisteredSigners(
        address[] memory signers
    ) external onlyOwner {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredSigners[signers[i]];
            emit DeletedAWSRegisteredSigner(signers[i]);
        }
    }
}
