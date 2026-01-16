// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType, UnsupportedServiceType} from "./types/Types.sol";
import {
    INitroEnclaveVerifier,
    VerifierJournal,
    ZkCoProcessorType,
    VerificationResult
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title  Verifies quotes from the AWS Nitro Enclave (TEE) and attests on-chain
 * @notice Contains the logic to verify zk proof of the attestation on-chain. It uses the EspressoNitroTEEVerifier contract
 *         from `automata` to verify the proof.
 */
contract EspressoNitroTEEVerifier is IEspressoNitroTEEVerifier, Ownable2Step {
    // Registered Batch Poster Enclave Hashes
    mapping(bytes32 => bool) public registeredBatchPosterEnclaveHashes;
    // Registered Caff Node Enclave Hashes
    mapping(bytes32 => bool) public registeredCaffNodeEnclaveHashes;
    // Registered Caff Nodes
    mapping(address => bool) public registeredCaffNodes;
    // Registered Batch Posters
    mapping(address => bool) public registeredBatchPosters;

    INitroEnclaveVerifier public _nitroEnclaveVerifier;

    constructor(INitroEnclaveVerifier nitroEnclaveVerifier) Ownable2Step() {
        require(address(nitroEnclaveVerifier) != address(0), "NitroEnclaveVerifier cannot be zero");
        _nitroEnclaveVerifier = nitroEnclaveVerifier;
        _transferOwnership(msg.sender);
    }

    /**
     * @notice This function registers a new Caff Node by verifying an attestation from the AWS Nitro Enclave (TEE)
     * The signer is not the caller of the function but the address which was generated inside the TEE.
     * @param output The public output of the ZK proof
     * @param proofBytes The cryptographic proof bytes over attestation
     */
    function registerCaffNode(bytes calldata output, bytes calldata proofBytes) external {
        (address enclaveAddress, bytes32 pcr0Hash) =
            _registerSigner(output, proofBytes, ServiceType.CaffNode);
        // Mark the signer as registered
        if (!registeredCaffNodes[enclaveAddress]) {
            registeredCaffNodes[enclaveAddress] = true;
            emit AWSNitroServiceRegistered(enclaveAddress, pcr0Hash, ServiceType.CaffNode);
        }
    }

    /**
     * @notice This function registers a new Batch Poster by verifying an attestation from the AWS Nitro Enclave (TEE)
     * @param output The public output of the ZK proof
     * @param proofBytes The cryptographic proof bytes over attestation
     */
    function registerBatchPoster(bytes calldata output, bytes calldata proofBytes) external {
        (address enclaveAddress, bytes32 pcr0Hash) =
            _registerSigner(output, proofBytes, ServiceType.BatchPoster);
        // Mark the signer as registered
        if (!registeredBatchPosters[enclaveAddress]) {
            registeredBatchPosters[enclaveAddress] = true;
            emit AWSNitroServiceRegistered(enclaveAddress, pcr0Hash, ServiceType.BatchPoster);
        }
    }

    /**
     * @notice This internal function verifies the ZK proof of the TEE attestation from the AWS Nitro Enclave
     * and returns the signer address and pcr0 hash
     * @param output The public output of the ZK proof
     * @param proofBytes The cryptographic proof bytes over attestation
     * @param service The service type (BatchPoster or CaffNode)
     */
    function _registerSigner(bytes calldata output, bytes calldata proofBytes, ServiceType service)
        internal
        returns (address, bytes32)
    {
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
        bytes32 pcr0Hash =
            keccak256(abi.encodePacked(journal.pcrs[0].value.first, journal.pcrs[0].value.second));

        if (service == ServiceType.BatchPoster) {
            if (!registeredBatchPosterEnclaveHashes[pcr0Hash]) {
                revert InvalidAWSEnclaveHash();
            }
        } else if (service == ServiceType.CaffNode) {
            if (!registeredCaffNodeEnclaveHashes[pcr0Hash]) {
                revert InvalidAWSEnclaveHash();
            }
        } else {
            revert UnsupportedServiceType();
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
        return (enclaveAddress, pcr0Hash);
    }

    /**
     * @notice This function allows the owner to set the enclave hash, setting valid to true will allow any enclave
     * with a valid pcr0 hash to register a signer (address which was generated inside the TEE). Setting valid to false
     * will further remove the enclave hash from the registered enclave hash list thus preventing any enclave with the given
     * hash from registering a signer.
     * @param enclaveHash The hash of the enclave
     * @param valid Whether the enclave hash is valid or not
     * @param service The service type (BatchPoster or CaffNode)
     */
    function setEnclaveHash(bytes32 enclaveHash, bool valid, ServiceType service)
        external
        onlyOwner
    {
        if (service == ServiceType.BatchPoster) {
            registeredBatchPosterEnclaveHashes[enclaveHash] = valid;
            emit AWSServiceEnclaveHashSet(enclaveHash, valid, ServiceType.BatchPoster);
        } else if (service == ServiceType.CaffNode) {
            registeredCaffNodeEnclaveHashes[enclaveHash] = valid;
            emit AWSServiceEnclaveHashSet(enclaveHash, valid, ServiceType.CaffNode);
        } else {
            revert UnsupportedServiceType();
        }
    }

    /**
     * @notice This function allows the owner to delete registered Caff Nodes
     * @param signers The list of signer addresses to be deleted
     */
    function deleteRegisteredCaffNodes(address[] memory signers) external onlyOwner {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredCaffNodes[signers[i]];
            emit DeletedAWSRegisteredService(signers[i], ServiceType.CaffNode);
        }
    }

    /*
     * @notice This function allows the owner to delete registered Batch Posters
     * @param signers The list of signer addresses to be deleted
     */
    function deleteRegisteredBatchPosters(address[] memory signers) external onlyOwner {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredBatchPosters[signers[i]];
            emit DeletedAWSRegisteredService(signers[i], ServiceType.BatchPoster);
        }
    }

    /*
     * @notice This function sets the NitroEnclaveVerifier contract address
     * @param nitroEnclaveVerifier The address of the NitroEnclaveVerifier contract
     */
    function setNitroEnclaveVerifier(address nitroEnclaveVerifier) external onlyOwner {
        if (nitroEnclaveVerifier == address(0)) {
            revert InvalidNitroEnclaveVerifierAddress();
        }
        _nitroEnclaveVerifier = INitroEnclaveVerifier(nitroEnclaveVerifier);
        emit NitroEnclaveVerifierSet(nitroEnclaveVerifier);
    }
}
