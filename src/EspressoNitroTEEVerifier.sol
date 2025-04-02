// // SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {NitroValidator} from "@nitro-validator/NitroValidator.sol";
import {LibBytes} from "@nitro-validator/LibBytes.sol";
import {LibCborElement, CborElement, CborDecode} from "@nitro-validator/CborDecode.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";

/*
    The code of this contract is inspired from SystemConfigGlobal.sol
    (https://github.com/base/op-enclave/blob/main/contracts/src/SystemConfigGlobal.sol)
*/
contract EspressoNitroTEEVerifier is NitroValidator, IEspressoNitroTEEVerifier, Ownable2Step {
    using CborDecode for bytes;
    using LibBytes for bytes;
    using LibCborElement for CborElement;

    mapping(bytes32 => bool) public registeredEnclaveHash;

    mapping(address => bool) public registeredSigners;

    constructor(bytes32 enclaveHash, CertManager certManager)
        NitroValidator(certManager)
        Ownable()
    {
        registeredEnclaveHash[enclaveHash] = true;
        _transferOwnership(msg.sender);
    }

    function registerSigner(bytes calldata attestationTbs, bytes calldata signature) external {
        Ptrs memory ptrs = validateAttestation(attestationTbs, signature);
        bytes32 pcr0Hash = attestationTbs.keccak(ptrs.pcrs[0]);
        if (!registeredEnclaveHash[pcr0Hash]) {
            revert InvalidEnclaveHash();
        }
        // The publicKey's first byte 0x04 byte followed which only determine if the public key is compressed or not.
        // so we ignore the first byte.
        bytes32 publicKeyHash =
            attestationTbs.keccak(ptrs.publicKey.start() + 1, ptrs.publicKey.length() - 1);
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
