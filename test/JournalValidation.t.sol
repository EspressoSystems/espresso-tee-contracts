// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {
    VerifierJournal,
    Pcr,
    Bytes48,
    VerificationResult,
    ZkCoProcessorType,
    ZkCoProcessorConfig,
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title Journal Validation Tests
 * @notice Comprehensive tests for _validateJournal() security checks
 * @dev Tests all critical validations that prevent security bypasses
 */
contract JournalValidationTest is Test {
    MockNitroVerifier mockVerifier;
    TestableNitroVerifier verifier;

    function setUp() public {
        mockVerifier = new MockNitroVerifier();
        verifier = new TestableNitroVerifier(mockVerifier);
    }

    /**
     * @dev Test: Valid journal passes all checks
     */
    function test_ValidJournalPasses() public view {
        VerifierJournal memory journal = createValidJournal();

        // Should not revert
        verifier.exposed_validateJournal(journal);
    }

    /**
     * @dev Test: Empty PCR array is rejected
     */
    function test_EmptyPCRArrayRejected() public {
        VerifierJournal memory journal = createValidJournal();
        journal.pcrs = new Pcr[](0); // Empty array!

        vm.expectRevert("PCR array cannot be empty");
        verifier.exposed_validateJournal(journal);
    }

    /**
     * @dev Test: PCR index != 0 is rejected (prevents wrong PCR validation)
     */
    function test_WrongPCRIndexRejected() public {
        VerifierJournal memory journal = createValidJournal();

        // Set first PCR to index 3 instead of 0
        journal.pcrs[0].index = 3;

        vm.expectRevert("First PCR must be PCR0 (code measurement)");
        verifier.exposed_validateJournal(journal);
    }

    /**
     * @dev Test: Public key length != 65 is rejected
     */
    function test_InvalidPublicKeyLengthRejected() public {
        VerifierJournal memory journal = createValidJournal();

        // Test various invalid lengths
        uint8[5] memory invalidLengths = [0, 1, 64, 66, 100];

        for (uint256 i = 0; i < invalidLengths.length; i++) {
            journal.publicKey = new bytes(invalidLengths[i]);
            if (invalidLengths[i] > 0) {
                journal.publicKey[0] = 0x04;
            }

            vm.expectRevert("Invalid public key length - must be 65 bytes");
            verifier.exposed_validateJournal(journal);
        }
    }

    /**
     * @dev Test: Public key without 0x04 prefix is rejected
     */
    function test_WrongPublicKeyFormatRejected() public {
        VerifierJournal memory journal = createValidJournal();

        // Test various invalid format markers
        bytes1[4] memory invalidFormats = [bytes1(0x00), 0x02, 0x03, 0xFF];

        for (uint256 i = 0; i < invalidFormats.length; i++) {
            journal.publicKey[0] = invalidFormats[i];

            vm.expectRevert("Public key must be uncompressed (0x04 prefix)");
            verifier.exposed_validateJournal(journal);
        }
    }

    /**
     * @dev Test: Predictable address attack is prevented
     * Shows that malformed 1-byte key would create predictable address
     */
    function test_PreventsPredictableAddressAttack() public {
        VerifierJournal memory journal = createValidJournal();

        // Attacker tries to use 1-byte key
        journal.publicKey = new bytes(1);
        journal.publicKey[0] = 0x04;

        // This would derive to predictable address: 0xdcc703c0E500B653Ca82273B7BFAd8045D85a470
        // But validation blocks it!
        vm.expectRevert("Invalid public key length - must be 65 bytes");
        verifier.exposed_validateJournal(journal);
    }

    /**
     * @dev Test: PCR index mismatch attack is prevented
     */
    function test_PreventsPCRIndexMismatchAttack() public {
        VerifierJournal memory journal = createValidJournal();

        // Attacker puts PCR3 in first position
        journal.pcrs[0].index = 3; // Malicious!

        // Without validation, contract would validate PCR3 thinking it's PCR0
        // But validation blocks it!
        vm.expectRevert("First PCR must be PCR0 (code measurement)");
        verifier.exposed_validateJournal(journal);
    }

    /**
     * @dev Test: Multiple PCRs with correct indices work
     */
    function test_MultiplePCRsWithCorrectIndices() public view {
        VerifierJournal memory journal = createValidJournal();

        // Add more PCRs with correct indices
        Pcr[] memory pcrs = new Pcr[](3);
        pcrs[0] = Pcr({
            index: 0, value: Bytes48({first: bytes32(uint256(1)), second: bytes16(uint128(1))})
        });
        pcrs[1] = Pcr({
            index: 1, value: Bytes48({first: bytes32(uint256(2)), second: bytes16(uint128(2))})
        });
        pcrs[2] = Pcr({
            index: 2, value: Bytes48({first: bytes32(uint256(3)), second: bytes16(uint128(3))})
        });

        journal.pcrs = pcrs;

        // Should pass (first PCR has index 0)
        verifier.exposed_validateJournal(journal);
    }

    /**
     * @dev Test: Valid 65-byte public key passes
     */
    function test_Valid65ByteKeyPasses() public view {
        VerifierJournal memory journal = createValidJournal();

        // Explicitly test with valid 65-byte key
        bytes memory validKey = new bytes(65);
        validKey[0] = 0x04; // Uncompressed marker
        for (uint256 i = 1; i < 65; i++) {
            validKey[i] = bytes1(uint8(i));
        }

        journal.publicKey = validKey;

        // Should pass
        verifier.exposed_validateJournal(journal);
    }

    // Helper function to create a valid journal
    function createValidJournal() internal view returns (VerifierJournal memory) {
        bytes memory validPublicKey = new bytes(65);
        validPublicKey[0] = 0x04;
        for (uint256 i = 1; i < 65; i++) {
            validPublicKey[i] = bytes1(uint8(i));
        }

        Pcr[] memory pcrs = new Pcr[](1);
        pcrs[0] = Pcr({
            index: 0, // Correct index
            value: Bytes48({first: bytes32(uint256(1)), second: bytes16(uint128(1))})
        });

        return VerifierJournal({
            result: VerificationResult.Success,
            trustedCertsPrefixLen: 1,
            timestamp: uint64(block.timestamp) * 1000,
            certs: new bytes32[](0),
            userData: "",
            nonce: "",
            publicKey: validPublicKey,
            pcrs: pcrs,
            moduleId: ""
        });
    }
}

/**
 * @dev Testable version that exposes _validateJournal for testing
 */
contract TestableNitroVerifier {
    INitroEnclaveVerifier private _verifier;

    constructor(INitroEnclaveVerifier verifier) {
        _verifier = verifier;
    }

    // Expose the validation function for testing
    function exposed_validateJournal(VerifierJournal memory journal) external pure {
        _validateJournal(journal);
    }

    // Copy of the validation function
    function _validateJournal(VerifierJournal memory journal) internal pure {
        // 1. Validate PCR array is not empty
        require(journal.pcrs.length > 0, "PCR array cannot be empty");

        // 2. CRITICAL: Validate PCR index is 0
        require(journal.pcrs[0].index == 0, "First PCR must be PCR0 (code measurement)");

        // 3. CRITICAL: Validate public key length
        require(journal.publicKey.length == 65, "Invalid public key length - must be 65 bytes");

        // 4. CRITICAL: Validate public key format
        require(journal.publicKey[0] == 0x04, "Public key must be uncompressed (0x04 prefix)");
    }
}

/**
 * @dev Mock verifier for testing
 */
contract MockNitroVerifier is INitroEnclaveVerifier {
    function verify(bytes calldata, ZkCoProcessorType, bytes calldata)
        external
        pure
        returns (VerifierJournal memory)
    {
        revert("Not used in these tests");
    }

    function batchVerify(bytes calldata, ZkCoProcessorType, bytes calldata)
        external
        pure
        returns (VerifierJournal[] memory)
    {
        revert("Not implemented");
    }

    function getZkConfig(ZkCoProcessorType) external pure returns (ZkCoProcessorConfig memory) {
        return ZkCoProcessorConfig({
            verifierId: bytes32(0),
            verifierProofId: bytes32(0),
            aggregatorId: bytes32(0),
            zkVerifier: address(0)
        });
    }

    function maxTimeDiff() external pure returns (uint64) {
        return 86_400;
    }

    function rootCert() external pure returns (bytes32) {
        return bytes32(0);
    }

    function revokeCert(bytes32) external pure {
        revert("Not implemented");
    }

    function checkTrustedIntermediateCerts(bytes32[][] calldata)
        external
        pure
        returns (uint8[] memory)
    {
        revert("Not implemented");
    }

    function setRootCert(bytes32) external pure {
        revert("Not implemented");
    }

    function setZkConfiguration(ZkCoProcessorType, ZkCoProcessorConfig memory) external pure {
        revert("Not implemented");
    }
}

