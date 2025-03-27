// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {NitroValidator} from "@nitro-validator/NitroValidator.sol";
import {CborDecode} from "@nitro-validator/CborDecode.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";

contract EspressoNitroTEEVerifier is
    Ownable2Step,
    IEspressoNitroTEEVerifier,
    NitroValidator
{
    using CborDecode for bytes;

    // Valid PCR0 values
    mapping(bytes32 => bool) public registeredEnclaveHash;
    // Valid signers
    mapping(address => bool) public registeredSigners;

    uint256 public constant MAX_ATTESTATION_AGE = 60 minutes;

    constructor(
        CertManager certManager,
        bytes memory enclaveHash,
        address preApprovedBatcherKey
    ) NitroValidator(certManager) Ownable(msg.sender) {
        if (preApprovedBatcherKey != address(0)) {
            registeredSigners[preApprovedBatcherKey] = true;
        }
        registeredEnclaveHash[keccak256(enclaveHash)] = true;
    }

    function registerEnclaveHash(bytes calldata pcr0) external onlyOwner {
        registeredEnclaveHash[keccak256(pcr0)] = true;
    }

    /*
        @notice Verify a signature from a registered signer
        @param hash The keccak256 hash of the signed message
        @param _signature The signature to be verified
    */
    function verifySignature(
        bytes calldata _signature,
        bytes32 hash
    ) public view {
        // https://github.com/ethereum/go-ethereum/issues/19751#issuecomment-504900739
        bytes memory signature = _signature;
        uint8 v = uint8(signature[64]);
        if (v == 0 || v == 1) {
            v += 27;
            signature[64] = bytes1(v);
        }

        address signer = ECDSA.recover(hash, signature);
        if (signer == address(0)) {
            revert InvalidSignature();
        }
        if (!registeredSigners[signer]) {
            revert InvalidSignerAddress();
        }
    }

    /*
        @notice Register a new signer by verifying an attestation from the AWS Nitro Enclave
        @notice Note that the attestation document is expected to be split into
        @notice attestation-to-be-signed and signature by the caller
        @param attestationTbs The attestation from the AWS Nitro Enclave
        @param signature The signature over attestationTbs
    */
    function registerSigner(
        bytes calldata attestationTbs,
        bytes calldata signature
    ) external {
        Ptrs memory ptrs = validateAttestation(attestationTbs, signature);
        bytes memory pcr0 = attestationTbs.slice(ptrs.pcrs[0]);

        if (!registeredEnclaveHash[keccak256(pcr0)]) {
            revert InvalidEnclaveHash();
        }
        if (ptrs.timestamp + MAX_ATTESTATION_AGE <= block.timestamp) {
            revert AttestationTooOld();
        }

        bytes memory publicKey = attestationTbs.slice(ptrs.publicKey);
        if (publicKey.length != 20) {
            revert InvalidPublicKey();
        }
        address signer = address(bytes20(publicKey));
        registeredSigners[signer] = true;
    }
}
