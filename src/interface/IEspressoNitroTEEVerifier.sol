// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {NitroValidator} from "@nitro-validator/NitroValidator.sol";
import {CborDecode} from "@nitro-validator/CborDecode.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

interface IEspressoNitroTEEVerifier {
    // This error is thrown when the signer address is invalid
    error InvalidSignerAddress();
    // This error is thrown when the signature is invalid
    error InvalidSignature();
    // This error is thrown when the PCR0 doesn't match
    error InvalidEnclaveHash();
    // This error is thrown when the attestation is too old
    error AttestationTooOld();
    // This error is thrown when the public key attached to the attestation is invalid
    error InvalidPublicKey();

    function registerEnclaveHash(bytes calldata pcr0) external;

    function verifySignature(
        bytes calldata _signature,
        bytes32 hash
    ) external view;

    function registerSigner(
        bytes calldata attestationTbs,
        bytes calldata signature
    ) external;
}
