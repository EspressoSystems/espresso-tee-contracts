// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {NitroValidator} from "@nitro-validator/NitroValidator.sol";
import {LibBytes} from "@nitro-validator/LibBytes.sol";
import {LibCborElement, CborElement, CborDecode} from "@nitro-validator/CborDecode.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";

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

    // Events
    event AttestationDataSubmitted(address indexed signer, bytes attestation, bytes signature);

    // PCR0 keccak hash
    mapping(bytes32 => bool) public registeredEnclaveHash;
    // Registered signers
    mapping(address => bool) public registeredSigners;
    // Certificate Manager
    CertManager _certManager;

    constructor(bytes32 enclaveHash, CertManager certManager)
        NitroValidator(certManager)
        Ownable()
    {
        _certManager = certManager;
        registeredEnclaveHash[enclaveHash] = true;
        _transferOwnership(msg.sender);
    }

    /**
     * @notice This function registers a new signer by verifying an attestation from the AWS Nitro Enclave (TEE)
     * @param attestation The attestation from the AWS Nitro Enclave (TEE)
     * @param signature The cryptographic signature over the COSESign1 payload (extracted from the attestation)
     */
    function registerSigner(bytes calldata attestation, bytes calldata signature) external {
        Ptrs memory ptrs = validateAttestation(attestation, signature);
        bytes32 pcr0Hash = attestation.keccak(ptrs.pcrs[0]);
        if (!registeredEnclaveHash[pcr0Hash]) {
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
        if (!registeredSigners[enclaveAddress]) {
            registeredSigners[enclaveAddress] = true;
            emit AWSSignerRegistered(enclaveAddress, pcr0Hash);
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

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external onlyOwner {
        registeredEnclaveHash[enclaveHash] = valid;
        emit AWSEnclaveHashSet(enclaveHash, valid);
    }

    function deleteRegisteredSigners(address[] memory signers) external onlyOwner {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredSigners[signers[i]];
            emit DeletedAWSRegisteredSigner(signers[i]);
        }
    }

    /**
     * @notice This function registers a new signer without attestation verification for reduced gas costs
     * @dev IMPORTANT: Attestation verification must be performed off-chain before calling this function
     * @param pcr0Hash The PCR0 hash to verify
     * @param attestation The attestation data (for transparency, not verified on-chain)
     * @param signature The signature data (for transparency, not verified on-chain)
     * @param enclaveAddress The address of the signer to register
     */
    function registerSignerWithoutAttestationVerification(bytes32 pcr0Hash, bytes calldata attestation, bytes calldata signature, address enclaveAddress) external onlyOwner {
        if (!registeredEnclaveHash[pcr0Hash]) {
            revert InvalidAWSEnclaveHash();
        }

        if (!registeredSigners[enclaveAddress]) {
            registeredSigners[enclaveAddress] = true;
            // Emit attestation data for public transparency and off-chain verification
            emit AWSSignerRegistered(enclaveAddress, pcr0Hash);
            emit AttestationDataSubmitted(enclaveAddress, attestation, signature);
        }
    }
}
