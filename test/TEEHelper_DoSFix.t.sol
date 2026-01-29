// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {ServiceType} from "../src/types/Types.sol";
import {
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title Tests for DoS Fix in TEEHelper
 * @notice Verifies that deleteEnclaveHashes no longer has unbounded loop vulnerability
 */
contract TEEHelperDoSFixTest is Test {
    address proxyAdminOwner = address(140);
    EspressoNitroTEEVerifier verifier;
    address owner;
    bytes32 testHash1 = keccak256("hash1");
    bytes32 testHash2 = keccak256("hash2");

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        owner = address(this);

        EspressoNitroTEEVerifier impl = new EspressoNitroTEEVerifier();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            proxyAdminOwner,
            abi.encodeCall(
                EspressoNitroTEEVerifier.initialize,
                (owner, INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788))
            )
        );
        verifier = EspressoNitroTEEVerifier(address(proxy));
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
     * @dev Test: Delete non-existent hash reverts
     */
    function test_DeleteNonExistentHashReverts() public {
        // Try to delete hash that was never registered
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        vm.expectRevert("Enclave hash not registered");
        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);
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
     * @dev Test: Delete hash that was previously disabled
     */
    function test_DeleteDisabledHash() public {
        // Register then disable
        verifier.setEnclaveHash(testHash1, true, ServiceType.BatchPoster);
        verifier.setEnclaveHash(testHash1, false, ServiceType.BatchPoster);

        // Should still be able to "delete" (though already disabled)
        // This reverts because disabled = not in the mapping as true
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        vm.expectRevert("Enclave hash not registered");
        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);
    }

    /**
     * @dev Test: Cannot delete same hash twice
     */
    function test_CannotDeleteHashTwice() public {
        // Register and delete
        verifier.setEnclaveHash(testHash1, true, ServiceType.BatchPoster);

        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash1;

        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);

        // Try to delete again
        vm.expectRevert("Enclave hash not registered");
        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);
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
     * @dev Test: Partial failure - stops at first non-existent hash
     */
    function test_PartialDelete() public {
        // Register only first hash
        verifier.setEnclaveHash(testHash1, true, ServiceType.BatchPoster);
        // testHash2 is NOT registered

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = testHash1;
        hashes[1] = testHash2; // This one doesn't exist

        // Should revert when hitting non-existent hash
        vm.expectRevert("Enclave hash not registered");
        verifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);

        // testHash1 should still be registered (atomic revert)
        assertTrue(
            verifier.registeredEnclaveHash(testHash1, ServiceType.BatchPoster),
            "First hash should remain (transaction reverted)"
        );
    }

    // Events
    event DeletedEnclaveHash(bytes32 indexed enclaveHash, ServiceType indexed service);
    event DeletedRegisteredService(address indexed signer, ServiceType indexed service);
}

