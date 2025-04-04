// // SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {NitroValidator} from "@nitro-validator/NitroValidator.sol";
import {LibBytes} from "@nitro-validator/LibBytes.sol";
import {LibCborElement, CborElement, CborDecode} from "@nitro-validator/CborDecode.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";

/**
 * @title  Verifies quotes from the AWS Nitro Enclave (TEE) and attests on-chain
 * @notice Contains the logic to verify a quote from the TEE and attest on-chain. It uses the NitroValidator contract
 *         from `base` to verify the quote. Along with some additional verification logic.
 *         (https://github.com/base/nitro-validator)
 * The code of this contract is inspired from SystemConfigGlobal.sol
 * (https://github.com/base/op-enclave/blob/main/contracts/src/SystemConfigGlobal.sol)
 */
contract EspressoNitroTEEVerifier is NitroValidator, IEspressoNitroTEEVerifier, Ownable2Step {
    using CborDecode for bytes;
    using LibBytes for bytes;
    using LibCborElement for CborElement;

    // PCR0 keccak hash
    mapping(bytes32 => bool) public registeredEnclaveHash;
    // Registered signers
    mapping(address => bool) public registeredSigners;

    constructor(bytes32 enclaveHash, CertManager certManager)
        NitroValidator(certManager)
        Ownable()
    {
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
            revert InvalidEnclaveHash();
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
            emit SignerRegistered(enclaveAddress, pcr0Hash);
        }
    }

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external onlyOwner {
        registeredEnclaveHash[enclaveHash] = valid;
        emit EnclaveHashSet(enclaveHash, valid);
    }

    function deleteRegisteredSigners(address[] memory signers) external onlyOwner {
        for (uint256 i = 0; i < signers.length; i++) {
            delete registeredSigners[signers[i]];
            emit DeletedRegisteredSigner(signers[i]);
        }
    }
}
