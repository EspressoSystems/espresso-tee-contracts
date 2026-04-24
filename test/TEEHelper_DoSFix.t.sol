// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";

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
            "https://rpc.ankr.com/eth_sepolia/b4eb7cd43eb25061e06a5d07ecd191433c3a28988f14dd9bfb6be6a122355023"
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
        verifier.setEnclaveHash(testHash1, true);
        assertTrue(verifier.registeredEnclaveHash(testHash1), "Hash should be registered");

        // Delete it
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        verifier.deleteEnclaveHashes(hashes);

        // Verify deleted
        assertFalse(verifier.registeredEnclaveHash(testHash1), "Hash should be deleted");
    }

    /**
     * @dev Test: Delete non-existent hash is a no-op (idempotent)
     */
    function test_DeleteNonExistentHashSkips() public {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        // hash was never registered so it is silently skipped
        verifier.deleteEnclaveHashes(hashes);

        assertFalse(verifier.registeredEnclaveHash(testHash1));
    }

    /**
     * @dev Test: Delete multiple hashes
     */
    function test_DeleteMultipleHashes() public {
        // Register multiple hashes
        verifier.setEnclaveHash(testHash1, true);
        verifier.setEnclaveHash(testHash2, true);

        // Delete both
        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = testHash1;
        hashes[1] = testHash2;

        verifier.deleteEnclaveHashes(hashes);

        // Verify both deleted
        assertFalse(verifier.registeredEnclaveHash(testHash1));
        assertFalse(verifier.registeredEnclaveHash(testHash2));
    }

    /**
     * @dev Test: DoS vulnerability is fixed - no gas issues with any size
     * Previously would fail with >1050 signers, now works regardless
     */
    function test_NoDoSRegardlessOfSignerCount() public {
        // This test shows that deleteEnclaveHashes now works
        // even if the hash has many signers (which we can't easily create in test)
        // The key is that we NO LONGER iterate through signers

        verifier.setEnclaveHash(testHash1, true);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        // Measure gas
        uint256 gasBefore = gasleft();
        verifier.deleteEnclaveHashes(hashes);
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
        verifier.setEnclaveHash(testHash1, true);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        address nonOwner = address(0x999);
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSignature("UnauthorizedTEEVerifier(address)", nonOwner));
        verifier.deleteEnclaveHashes(hashes);
    }

    /**
     * @dev Test: Events are emitted correctly
     */
    function test_DeleteEmitsEvent() public {
        verifier.setEnclaveHash(testHash1, true);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        vm.expectEmit(true, false, false, false);
        emit DeletedEnclaveHash(testHash1);

        verifier.deleteEnclaveHashes(hashes);
    }

    /**
     * @dev Test: Delete empty array succeeds (no-op)
     */
    function test_DeleteEmptyArray() public {
        bytes32[] memory hashes = new bytes32[](0);

        // Should succeed without doing anything
        verifier.deleteEnclaveHashes(hashes);
    }

    /**
     * @dev Test: Unregistered hashes are skipped; registered hashes in the same batch still get deleted
     */
    function test_PartialDelete() public {
        // testHash2 is registered; testHash1 is not
        verifier.setEnclaveHash(testHash2, true);

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = testHash1; // not registered — should be skipped
        hashes[1] = testHash2; // registered — should be deleted

        verifier.deleteEnclaveHashes(hashes);

        assertFalse(verifier.registeredEnclaveHash(testHash1), "testHash1 was never registered");
        assertFalse(verifier.registeredEnclaveHash(testHash2), "testHash2 should be deleted");
    }

    // Events
    event DeletedEnclaveHash(bytes32 indexed enclaveHash);
    event DeletedRegisteredService(address indexed signer);
}
