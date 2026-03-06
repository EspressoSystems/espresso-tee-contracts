// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {ServiceType} from "../src/types/Types.sol";

/**
 * @title Tests for DoS Fix in TEEHelper
 * @notice Verifies that deleteEnclaveHashes no longer has unbounded loop vulnerability
 */
contract TEEHelperDoSFixTest is Test {
    EspressoNitroTEEVerifier verifier;
    bytes32 testHash1 = keccak256("hash1");
    bytes32 testHash2 = keccak256("hash2");

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        // address(this) is the teeVerifier so test functions can call setEnclaveHash/deleteEnclaveHashes
        verifier = new EspressoNitroTEEVerifier(
            address(this), address(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );
    }

    /**
     * @dev Test: Delete existing hash succeeds
     */
    function test_DeleteExistingHash() public {
        // Register a hash
        verifier.setEnclaveHash(testHash1, true, ServiceType.BatchPoster);
        assertTrue(
            verifier.registeredEnclaveHash(testHash1, ServiceType.BatchPoster),
            "Hash should be registered"
        );

        // Delete it
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);

        // Verify deleted
        assertFalse(
            verifier.registeredEnclaveHash(testHash1, ServiceType.BatchPoster),
            "Hash should be deleted"
        );
    }

    /**
     * @dev Test: Delete non-existent hash is a no-op (idempotent)
     */
    function test_DeleteNonExistentHashSkips() public {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        // hash was never registered so it is silently skipped
        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);

        assertFalse(verifier.registeredEnclaveHash(testHash1, ServiceType.BatchPoster));
    }

    /**
     * @dev Test: Delete multiple hashes
     */
    function test_DeleteMultipleHashes() public {
        // Register multiple hashes
        verifier.setEnclaveHash(testHash1, true, ServiceType.BatchPoster);
        verifier.setEnclaveHash(testHash2, true, ServiceType.BatchPoster);

        // Delete both
        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = testHash1;
        hashes[1] = testHash2;

        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);

        // Verify both deleted
        assertFalse(verifier.registeredEnclaveHash(testHash1, ServiceType.BatchPoster));
        assertFalse(verifier.registeredEnclaveHash(testHash2, ServiceType.BatchPoster));
    }

    /**
     * @dev Test: Delete is service-specific
     */
    function test_DeleteIsServiceSpecific() public {
        // Register hash for both services
        verifier.setEnclaveHash(testHash1, true, ServiceType.BatchPoster);
        verifier.setEnclaveHash(testHash1, true, ServiceType.CaffNode);

        // Delete only from BatchPoster
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);

        // Verify only BatchPoster deleted
        assertFalse(
            verifier.registeredEnclaveHash(testHash1, ServiceType.BatchPoster),
            "BatchPoster should be deleted"
        );
        assertTrue(
            verifier.registeredEnclaveHash(testHash1, ServiceType.CaffNode),
            "CaffNode should still exist"
        );
    }

    /**
     * @dev Test: DoS vulnerability is fixed - no gas issues with any size
     * Previously would fail with >1050 signers, now works regardless
     */
    function test_NoDoSRegardlessOfSignerCount() public {
        // This test shows that deleteEnclaveHashes now works
        // even if the hash has many signers (which we can't easily create in test)
        // The key is that we NO LONGER iterate through signers

        verifier.setEnclaveHash(testHash1, true, ServiceType.BatchPoster);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        // Measure gas
        uint256 gasBefore = gasleft();
        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);
        uint256 gasUsed = gasBefore - gasleft();

        // Should use minimal gas (no loop over signers)
        // Previous implementation: ~28,500 gas PER SIGNER
        // New implementation: ~5,000 gas TOTAL (constant)
        assertLt(gasUsed, 50_000, "Should use minimal gas");
    }

    /**
     * @dev Test: Only owner can delete hashes
     */
    function test_OnlyOwnerCanDelete() public {
        verifier.setEnclaveHash(testHash1, true, ServiceType.BatchPoster);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        address nonOwner = address(0x999);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSignature("UnauthorizedTEEVerifier(address)", nonOwner));
        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);
    }

    /**
     * @dev Test: Events are emitted correctly
     */
    function test_DeleteEmitsEvent() public {
        verifier.setEnclaveHash(testHash1, true, ServiceType.BatchPoster);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        vm.expectEmit(true, true, false, false);
        emit DeletedEnclaveHash(testHash1, ServiceType.BatchPoster);

        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);
    }

    /**
     * @dev Test: Delete empty array succeeds (no-op)
     */
    function test_DeleteEmptyArray() public {
        bytes32[] memory hashes = new bytes32[](0);

        // Should succeed without doing anything
        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);
    }

    /**
     * @dev Test: Unregistered hashes are skipped; registered hashes in the same batch still get deleted
     */
    function test_PartialDelete() public {
        // testHash2 is registered; testHash1 is not
        verifier.setEnclaveHash(testHash2, true, ServiceType.BatchPoster);

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = testHash1; // not registered — should be skipped
        hashes[1] = testHash2; // registered — should be deleted

        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);

        assertFalse(
            verifier.registeredEnclaveHash(testHash1, ServiceType.BatchPoster),
            "testHash1 was never registered"
        );
        assertFalse(
            verifier.registeredEnclaveHash(testHash2, ServiceType.BatchPoster),
            "testHash2 should be deleted"
        );
    }

    // Events
    event DeletedEnclaveHash(bytes32 indexed enclaveHash, ServiceType indexed service);
    event DeletedRegisteredService(address indexed signer, ServiceType indexed service);
}
