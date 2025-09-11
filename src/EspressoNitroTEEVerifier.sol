// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {NitroValidator} from "@nitro-validator/NitroValidator.sol";
import {LibBytes} from "@nitro-validator/LibBytes.sol";
import {LibCborElement, CborElement, CborDecode} from "@nitro-validator/CborDecode.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType, Unimplemented} from "./types/Types.sol";

/**
 * @title  Verifies quotes from the AWS Nitro Enclave (TEE) and attests on-chain
 * @notice Contains the logic to verify an attestation and signature from the TEE and attest on-chain. It uses the NitroValidator contract
 *         from `base` to verify the quote. Along with some additional verification logic.
 *         (https://github.com/base/nitro-validator)
 * The code of this contract is inspired from SystemConfigGlobal.sol
 * (https://github.com/base/op-enclave/blob/main/contracts/src/SystemConfigGlobal.sol)
 */
contract EspressoNitroTEEVerifier is NitroValidator, IEspressoNitroTEEVerifier, Ownable2Step {
    using CborDecode for bytes;
    using LibBytes for bytes;
    using LibCborElement for CborElement;

    // PCR0 keccak hash for batch posters
    mapping(bytes32 => bool) public registeredBatchPosterEnclaveHashes;
    mapping(bytes32 => bool) public registeredCaffNodeEnclaveHashes;
    // Registered Caff Nodes
    mapping(address => bool) public registeredCaffNodes;
    // Registered Batch Posters
    mapping(address => bool) public registeredBatchPosters;
    // Certificate Manager
    CertManager _certManager;

    constructor(bytes32 enclaveHash, CertManager certManager)
        NitroValidator(certManager)
        Ownable()
    {
        _certManager = certManager;
        registeredBatchPosterEnclaveHashes[enclaveHash] = true; // TODO: modify this constructor after some review on this. 
        _transferOwnership(msg.sender);
    }

    /**
     * @notice This function registers a new Batch Poster by verifying an attestation from the AWS Nitro Enclave (TEE)
     * @param attestation The attestation from the AWS Nitro Enclave (TEE)
     * @param signature The cryptographic signature over the COSESign1 payload (extracted from the attestation)
     */
    function registerCaffNode(bytes calldata attestation, bytes calldata signature) external {
        revert Unimplemented();
    }
    /**
     * @notice This function registers a new Batch Poster by verifying an attestation from the AWS Nitro Enclave (TEE)
     * @param attestation The attestation from the AWS Nitro Enclave (TEE)
     * @param signature The cryptographic signature over the COSESign1 payload (extracted from the attestation)
     */
    function registerBatchPoster(bytes calldata attestation, bytes calldata signature) external {
        Ptrs memory ptrs = validateAttestation(attestation, signature);
        bytes32 pcr0Hash = attestation.keccak(ptrs.pcrs[0]);
        if (!registeredBatchPosterEnclaveHashes[pcr0Hash]) {
            revert InvalidAWSEnclaveHash();
        }
        // The publicKey's first byte 0x04 byte followed which only determine if the public key is compressed or not.
        // so we ignore the first byte.
        bytes32 publicKeyHash =
            attestation.keccak(ptrs.publicKey.start() + 1, ptrs.publicKey.length() - 1);

        // Note: We take the keccak hash first to derive the address.
        // This is the same which the go ethereum crypto library is doing for PubkeyToAddress()
        address enclaveAddress = address(uint160(uint256(publicKeyHash)));

        // Mark the signer as registered
        if (!registeredBatchPosters[enclaveAddress]) {
            registeredBatchPosters[enclaveAddress] = true;
            emit AWSServiceRegistered(enclaveAddress, pcr0Hash, ServiceType.BatchPoster);
        }
    }

    /**
     * @notice This function verifies a AWS Nitro Attestations CA Certificate on chain
     * @param certificate The certificate from the attestation
     * @param parentCertHash The keccak256 hash over the parent certificate
     */
    function verifyCACert(bytes calldata certificate, bytes32 parentCertHash) external {
        _certManager.verifyCACert(certificate, parentCertHash);
    }

    /**
     * @notice This function verifies a AWS Nitro Attestations Client Certificate on chain
     * @param certificate The certificate from the attestation
     * @param parentCertHash The keccak256 hash over the parent certificate
     */
    function verifyClientCert(bytes calldata certificate, bytes32 parentCertHash) external {
        _certManager.verifyClientCert(certificate, parentCertHash);
    }

    /**
     * @notice This function is a readonly function to check if a certificate is already verified on chain
     * @param certHash The certificate keccak256 hash
     */
    function certVerified(bytes32 certHash) external view returns (bool) {
        bytes memory verifiedBytes = _certManager.verified(certHash);
        return verifiedBytes.length > 0;
    }

    function setEnclaveHash(bytes32 enclaveHash, bool valid, ServiceType service) external onlyOwner {
        if (service == ServiceType.CaffNode){
            revert Unimplemented();
        }
        registeredBatchPosterEnclaveHashes[enclaveHash] = valid;
        emit AWSServiceEnclaveHashSet(enclaveHash, valid, ServiceType.BatchPoster);
    }

    function deleteRegisteredCaffNodes(address[] memory signers) external onlyOwner {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredCaffNodes[signers[i]];
            emit DeletedAWSRegisteredService(signers[i], ServiceType.CaffNode);
        }
    }

    function deleteRegisteredBatchPosters(address[] memory signers) external onlyOwner {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredBatchPosters[signers[i]];
            emit DeletedAWSRegisteredService(signers[i], ServiceType.BatchPoster);
        }
    }
}
