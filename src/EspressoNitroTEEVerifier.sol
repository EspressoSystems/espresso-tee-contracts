// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {
    INitroEnclaveVerifier,
    VerifierJournal,
    ZkCoProcessorType
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title  Verifies quotes from the AWS Nitro Enclave (TEE) and attests on-chain
 * @notice Contains the logic to verify zk proof of the attestation on-chain. It uses the EspressoNitroTEEVerifier contract
 *         from `automata` to verify the proof.
 */
contract EspressoNitroTEEVerifier is IEspressoNitroTEEVerifier, Ownable2Step {
    // PCR0 keccak hash
    mapping(bytes32 => bool) public registeredEnclaveHash;
    // Registered signers
    mapping(address => bool) public registeredSigners;
    // Nitro Enclave Verifier
    INitroEnclaveVerifier public _nitroEnclaveVerifier;

    constructor(bytes32 enclaveHash, INitroEnclaveVerifier nitroEnclaveVerifier) Ownable2Step() {
        require(enclaveHash != bytes32(0), "Enclave hash cannot be zero");
        require(address(nitroEnclaveVerifier) != address(0), "NitroEnclaveVerifier cannot be zero");
        _nitroEnclaveVerifier = nitroEnclaveVerifier;
        registeredEnclaveHash[enclaveHash] = true;
        _transferOwnership(msg.sender);
    }

    /**
     * @notice This function registers a new signer by verifying an attestation from the AWS Nitro Enclave (TEE)
     * The signer is not the caller of the function but the address which was generated inside the TEE.
     * @param output The public output of the ZK proof
     * @param proofBytes The cryptographic proof bytes over attestation
     */
    function registerSigner(bytes calldata output, bytes calldata proofBytes) external {
        VerifierJournal memory journal = _nitroEnclaveVerifier.verify(
            output,
            // Currently only Succinct ZK coprocessor is supported
            ZkCoProcessorType.Succinct,
            proofBytes
        );
        // we hash the pcr0 value to get the the pcr0Hash and then
        // check if the given hash has been registered in the contract by the owner
        // this allows us to verify that the registerSigner request is coming from a TEE
        // which is trusted
        bytes32 pcr0Hash =
            keccak256(abi.encodePacked(journal.pcrs[0].value.first, journal.pcrs[0].value.second));
        if (!registeredEnclaveHash[pcr0Hash]) {
            revert InvalidAWSEnclaveHash();
        }

        // The publicKey's first byte 0x04 byte followed which only determine if the public key is compressed or not.
        // so we ignore the first byte.
        bytes memory publicKeyWithoutPrefix = new bytes(journal.publicKey.length - 1);
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

    /**
     * @notice This function allows the owner to set the enclave hash, setting valid to true will allow any enclave
     * with a valid pcr0 hash to register a signer (address which was generated inside the TEE). Setting valid to false
     * will further remove the enclave hash from the registered enclave hash list thus preventing any enclave with the given
     * hash from registering a signer.
     * @param enclaveHash The hash of the enclave
     * @param valid Whether the enclave hash is valid or not
     */
    function setEnclaveHash(bytes32 enclaveHash, bool valid) external onlyOwner {
        require(enclaveHash != bytes32(0), "Enclave hash cannot be zero");
        registeredEnclaveHash[enclaveHash] = valid;
        emit AWSEnclaveHashSet(enclaveHash, valid);
    }

    function deleteRegisteredSigners(address[] memory signers) external onlyOwner {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredSigners[signers[i]];
            emit DeletedAWSRegisteredSigner(signers[i]);
        }
    }
}
