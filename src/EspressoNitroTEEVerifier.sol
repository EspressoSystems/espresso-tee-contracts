// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {
    EnumerableSet
} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {
    IEspressoNitroTEEVerifier
} from "./interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType, UnsupportedServiceType} from "./types/Types.sol";
import {
    INitroEnclaveVerifier,
    VerifierJournal,
    ZkCoProcessorType,
    VerificationResult
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {TEEHelper} from "./TEEHelper.sol";

/**
 * @title  Verifies quotes from the AWS Nitro Enclave (TEE) and attests on-chain
 * @notice Contains the logic to verify zk proof of the attestation on-chain. It uses the EspressoNitroTEEVerifier contract
 *         from `automata` to verify the proof.
 */
contract EspressoNitroTEEVerifier is IEspressoNitroTEEVerifier, TEEHelper {
    using EnumerableSet for EnumerableSet.AddressSet;
    INitroEnclaveVerifier public _nitroEnclaveVerifier;

    constructor(INitroEnclaveVerifier nitroEnclaveVerifier) TEEHelper() {
        require(
            address(nitroEnclaveVerifier) != address(0),
            "NitroEnclaveVerifier cannot be zero"
        );
        _nitroEnclaveVerifier = nitroEnclaveVerifier;
    }

    /**
     * @notice This function registers a new Service by verifying an attestation from the AWS Nitro Enclave (TEE)
     * The signer is not the caller of the function but the address which was generated inside the TEE.
     * @param output The public output of the ZK proof
     * @param proofBytes The cryptographic proof bytes over attestation
     * @param service The service type (BatchPoster or CaffNode)
     */
    function registerService(
        bytes calldata output,
        bytes calldata proofBytes,
        ServiceType service
    ) external onlySupportedServiceType(service) {
        VerifierJournal memory journal = _nitroEnclaveVerifier.verify(
            output,
            // Currently only Succinct ZK coprocessor is supported
            ZkCoProcessorType.Succinct,
            proofBytes
        );

        if (journal.result != VerificationResult.Success) {
            revert VerificationFailed(journal.result);
        }

        // we hash the pcr0 value to get the the pcr0Hash and then
        // check if the given hash has been registered in the contract by the owner
        // this allows us to verify that the registerSigner request is coming from a TEE
        // which is trusted
        bytes32 pcr0Hash = keccak256(
            abi.encodePacked(
                journal.pcrs[0].value.first,
                journal.pcrs[0].value.second
            )
        );

        if (!registeredEnclaveHashes[service][pcr0Hash]) {
            revert InvalidEnclaveHash(pcr0Hash, service);
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
        if (!registeredSigners[service][enclaveAddress]) {
            registeredSigners[service][enclaveAddress] = true;
            enclaveHashToSigner[service][pcr0Hash].add(enclaveAddress);
            emit ServiceRegistered(enclaveAddress, pcr0Hash, service);
        }
    }

    /*
     * @notice This function sets the NitroEnclaveVerifier contract address
     * @param nitroEnclaveVerifier The address of the NitroEnclaveVerifier contract
     */
    function setNitroEnclaveVerifier(
        address nitroEnclaveVerifier
    ) external onlyOwner {
        if (nitroEnclaveVerifier == address(0)) {
            revert InvalidNitroEnclaveVerifierAddress();
        }
        _nitroEnclaveVerifier = INitroEnclaveVerifier(nitroEnclaveVerifier);
        emit NitroEnclaveVerifierSet(nitroEnclaveVerifier);
    }
}
