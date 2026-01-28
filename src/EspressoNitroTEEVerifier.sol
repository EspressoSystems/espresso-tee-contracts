// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType} from "./types/Types.sol";
import {
    INitroEnclaveVerifier,
    VerifierJournal,
    ZkCoProcessorType,
    VerificationResult
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {TEEHelper} from "./TEEHelper.sol";

/**
 * @title  Verifies quotes from the AWS Nitro Enclave (TEE) and attests on-chain
 * @notice Contains the logic to verify zk proof of the attestation on-chain. It uses the EspressoNitroTEEVerifier contract
 *         from `automata` to verify the proof.
 */
contract EspressoNitroTEEVerifier is IEspressoNitroTEEVerifier, TEEHelper {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @custom:storage-location erc7201:espresso.storage.EspressoNitroTEEVerifier
    struct EspressoNitroTEEVerifierStorage {
        INitroEnclaveVerifier nitroEnclaveVerifier;
    }

    // keccak256(abi.encode(uint256(keccak256("espresso.storage.EspressoNitroTEEVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ESPRESSO_NITRO_TEE_VERIFIER_STORAGE_SLOT =
        0x719e73d7233ff4744eafaba0d5366ca21ea408c038f043b446a24c6ec313a800;

    function _nitroLayout() private pure returns (EspressoNitroTEEVerifierStorage storage $) {
        assembly {
            $.slot := ESPRESSO_NITRO_TEE_VERIFIER_STORAGE_SLOT
        }
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address teeVerifier_, INitroEnclaveVerifier nitroEnclaveVerifier_)
        external
        initializer
    {
        __TEEHelper_init(teeVerifier_);
        _setNitroEnclaveVerifier(address(nitroEnclaveVerifier_));
    }

    /**
     * @notice This function registers a new Service by verifying an attestation from the AWS Nitro Enclave (TEE)
     * The signer is not the caller of the function but the address which was generated inside the TEE.
     * @param output The public output of the ZK proof
     * @param proofBytes The cryptographic proof bytes over attestation
     * @param service The service type (BatchPoster or CaffNode)
     */
    function registerService(bytes calldata output, bytes calldata proofBytes, ServiceType service)
        external
    {
        VerifierJournal memory journal = _nitroLayout().nitroEnclaveVerifier
            .verify(
                output,
                // Currently only Succinct ZK coprocessor is supported
                ZkCoProcessorType.Succinct,
                proofBytes
            );

        if (journal.result != VerificationResult.Success) {
            revert VerificationFailed(journal.result);
        }

        // SECURITY: Validate journal format and integrity (Defense in Depth)
        _validateJournal(journal);

        // we hash the pcr0 value to get the the pcr0Hash and then
        // check if the given hash has been registered in the contract by the tee verifier
        // this allows us to verify that the registerSigner request is coming from a TEE
        // which is trusted
        bytes32 pcr0Hash =
            keccak256(abi.encodePacked(journal.pcrs[0].value.first, journal.pcrs[0].value.second));

        if (!_layout().registeredEnclaveHashes[service][pcr0Hash]) {
            revert InvalidEnclaveHash(pcr0Hash, service);
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
        if (!_layout().registeredServices[service][enclaveAddress]) {
            TEEHelperStorage storage $ = _layout();
            $.registeredServices[service][enclaveAddress] = true;
            $.enclaveHashToSigner[service][pcr0Hash].add(enclaveAddress);
            
            // Track which enclave hash this signer belongs to (for automatic revocation)
            $.signerToEnclaveHash[service][enclaveAddress] = pcr0Hash;

            emit ServiceRegistered(enclaveAddress, pcr0Hash, service);
        }
    }

    /**
     * @notice Validates the VerifierJournal format and integrity
     * @dev Implements defense-in-depth by validating critical fields even if ZK circuit validates them
     * @param journal The journal returned from ZK proof verification
     *
     * Security validations:
     * 1. PCR array bounds - Ensures we can safely access journal.pcrs[0]
     * 2. PCR index correctness - Ensures pcrs[0] is actually PCR0 (code measurement), not PCR3 or other
     * 3. Public key length - Ensures 65-byte format (prevents predictable address attacks)
     * 4. Public key format - Ensures uncompressed format (0x04 prefix)
     *
     * Why validate even if ZK circuit should validate:
     * - Defense in depth: Multiple security layers
     * - Protection against ZK circuit bugs or gaps
     * - Explicit documentation of security requirements
     * - Minimal gas cost (~500 gas) for critical protection
     */
    function _validateJournal(VerifierJournal memory journal) internal pure {
        // 1. Validate PCR array is not empty (prevents out-of-bounds on journal.pcrs[0])
        require(journal.pcrs.length > 0, "PCR array cannot be empty");

        // 2. CRITICAL: Validate PCR index is 0 (prevents validating wrong PCR!)
        // Without this check, an attacker could put PCR3 in position 0
        // Contract would validate PCR3 (benign) while PCR0 (code) is compromised
        require(journal.pcrs[0].index == 0, "First PCR must be PCR0 (code measurement)");

        // 3. CRITICAL: Validate public key length (prevents predictable address attacks)
        // Malformed keys (e.g., length=1) would hash to predictable addresses
        // Anyone could compute these addresses without needing a TEE
        require(journal.publicKey.length == 65, "Invalid public key length - must be 65 bytes");

        // 4. CRITICAL: Validate public key format (ensures correct address derivation)
        // Must be uncompressed ECDSA format: 0x04 + 32-byte X + 32-byte Y
        // Other formats would derive incorrect addresses
        require(journal.publicKey[0] == 0x04, "Public key must be uncompressed (0x04 prefix)");
    }

    /*
     * @notice This function sets the NitroEnclaveVerifier contract address
     * @param nitroEnclaveVerifier The address of the NitroEnclaveVerifier contract
     */
    function setNitroEnclaveVerifier(address nitroEnclaveVerifier_) external onlyTEEVerifier {
        _setNitroEnclaveVerifier(nitroEnclaveVerifier_);
    }

    function _setNitroEnclaveVerifier(address nitroEnclaveVerifier_) internal {
        if (nitroEnclaveVerifier_ == address(0)) {
            revert InvalidNitroEnclaveVerifierAddress();
        }
        _nitroLayout().nitroEnclaveVerifier = INitroEnclaveVerifier(nitroEnclaveVerifier_);
        emit NitroEnclaveVerifierSet(nitroEnclaveVerifier_);
    }

    /**
     * @notice Get the NitroEnclaveVerifier address
     * @return The NitroEnclaveVerifier interface
     */
    function nitroEnclaveVerifier() external view returns (INitroEnclaveVerifier) {
        return _nitroLayout().nitroEnclaveVerifier;
    }
}
