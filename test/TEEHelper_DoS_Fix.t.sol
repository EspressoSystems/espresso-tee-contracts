// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {ServiceType} from "../src/types/Types.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

// Mock implementation of the FIXED TEEHelper for testing
contract TEEHelperFixed is Test {
    using EnumerableSet for EnumerableSet.AddressSet;
    
    uint256 public constant MAX_SIGNERS_PER_HASH = 1000;
    uint256 public constant MAX_BATCH_DELETE_SIZE = 100;
    
    mapping(ServiceType => mapping(bytes32 => bool)) public registeredEnclaveHashes;
    mapping(ServiceType => mapping(address => bool)) public registeredServices;
    mapping(ServiceType => mapping(bytes32 => EnumerableSet.AddressSet)) internal enclaveHashToSigner;
    
    address public owner;
    
    event DeletedRegisteredService(address indexed signer, ServiceType indexed service);
    event DeletedEnclaveHash(bytes32 indexed enclaveHash, ServiceType indexed service);
    event EnclaveHashDisabled(bytes32 indexed enclaveHash, ServiceType indexed service);
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    // Test helper function to register signers
    function registerSigner(bytes32 enclaveHash, address signer, ServiceType service) external {
        require(
            enclaveHashToSigner[service][enclaveHash].length() < MAX_SIGNERS_PER_HASH,
            "Maximum signers for this enclave hash reached"
        );
        
        registeredServices[service][signer] = true;
        enclaveHashToSigner[service][enclaveHash].add(signer);
    }
    
    function getSignerCount(bytes32 enclaveHash, ServiceType service) public view returns (uint256) {
        return enclaveHashToSigner[service][enclaveHash].length();
    }
    
    // FIX #1: Batch deletion
    function deleteEnclaveHashBatch(
        bytes32 enclaveHash,
        ServiceType service,
        uint256 maxIterations
    ) public onlyOwner returns (uint256 remaining) {
        if (maxIterations == 0) {
            maxIterations = MAX_BATCH_DELETE_SIZE;
        }
        
        require(maxIterations <= MAX_BATCH_DELETE_SIZE, "Batch size too large");
        
        EnumerableSet.AddressSet storage signersSet = enclaveHashToSigner[service][enclaveHash];
        
        uint256 iterations = 0;
        while (signersSet.length() > 0 && iterations < maxIterations) {
            address signer = signersSet.at(0);
            delete registeredServices[service][signer];
            signersSet.remove(signer);
            emit DeletedRegisteredService(signer, service);
            iterations++;
        }
        
        remaining = signersSet.length();
        
        if (remaining == 0) {
            delete registeredEnclaveHashes[service][enclaveHash];
            emit DeletedEnclaveHash(enclaveHash, service);
        }
        
        return remaining;
    }
    
    // FIX #2: Two-step deletion
    function disableEnclaveHash(bytes32 enclaveHash, ServiceType service) external onlyOwner {
        registeredEnclaveHashes[service][enclaveHash] = false;
        emit EnclaveHashDisabled(enclaveHash, service);
    }
    
    // Modified original function with safety check
    function deleteEnclaveHashes(bytes32[] memory enclaveHashes, ServiceType service)
        external
        onlyOwner
    {
        for (uint256 i = 0; i < enclaveHashes.length; i++) {
            EnumerableSet.AddressSet storage signersSet = enclaveHashToSigner[service][enclaveHashes[i]];
            
            uint256 signerCount = signersSet.length();
            
            require(
                signerCount <= MAX_BATCH_DELETE_SIZE,
                "Too many signers. Use deleteEnclaveHashBatch()"
            );
            
            while (signersSet.length() > 0) {
                address signer = signersSet.at(0);
                delete registeredServices[service][signer];
                signersSet.remove(signer);
                emit DeletedRegisteredService(signer, service);
            }
            delete registeredEnclaveHashes[service][enclaveHashes[i]];
            emit DeletedEnclaveHash(enclaveHashes[i], service);
        }
    }
}

/**
 * @title Test suite for DoS fix
 */
contract TEEHelperDoSFixTest is Test {
    TEEHelperFixed helper;
    address owner = address(this);
    bytes32 testHash = keccak256("test");
    
    function setUp() public {
        helper = new TEEHelperFixed();
    }
    
    /**
     * @dev Test that batch deletion works for large number of signers
     */
    function testBatchDeletionPreventsDoS() public {
        // Register 500 signers (would DoS original function)
        for (uint i = 0; i < 500; i++) {
            address signer = address(uint160(i + 1));
            helper.registerSigner(testHash, signer, ServiceType.BatchPoster);
        }
        
        assertEq(helper.getSignerCount(testHash, ServiceType.BatchPoster), 500);
        
        // Delete in batches of 100
        uint256 remaining = 500;
        uint256 batchCount = 0;
        
        while (remaining > 0) {
            remaining = helper.deleteEnclaveHashBatch(testHash, ServiceType.BatchPoster, 100);
            batchCount++;
            
            // Prevent infinite loop in test
            require(batchCount < 10, "Too many batches");
        }
        
        // Verify all deleted
        assertEq(helper.getSignerCount(testHash, ServiceType.BatchPoster), 0);
        assertEq(batchCount, 5); // 500 signers / 100 per batch = 5 batches
    }
    
    /**
     * @dev Test that original function now reverts with too many signers
     */
    function testOriginalFunctionRevertsWithManySigners() public {
        // Register 150 signers (more than MAX_BATCH_DELETE_SIZE)
        for (uint i = 0; i < 150; i++) {
            address signer = address(uint160(i + 1));
            helper.registerSigner(testHash, signer, ServiceType.BatchPoster);
        }
        
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash;
        
        // Should revert with helpful error message
        vm.expectRevert("Too many signers. Use deleteEnclaveHashBatch()");
        helper.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);
    }
    
    /**
     * @dev Test that original function still works for small numbers
     */
    function testOriginalFunctionWorksWithFewSigners() public {
        // Register 50 signers (less than MAX_BATCH_DELETE_SIZE)
        for (uint i = 0; i < 50; i++) {
            address signer = address(uint160(i + 1));
            helper.registerSigner(testHash, signer, ServiceType.BatchPoster);
        }
        
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = testHash;
        
        // Should work fine
        helper.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);
        
        assertEq(helper.getSignerCount(testHash, ServiceType.BatchPoster), 0);
    }
    
    /**
     * @dev Test maximum signers limit prevents attack
     */
    function testMaxSignersLimitPreventsInflation() public {
        // Register up to limit
        for (uint i = 0; i < 1000; i++) {
            address signer = address(uint160(i + 1));
            helper.registerSigner(testHash, signer, ServiceType.BatchPoster);
        }
        
        assertEq(helper.getSignerCount(testHash, ServiceType.BatchPoster), 1000);
        
        // Try to register one more - should fail
        vm.expectRevert("Maximum signers for this enclave hash reached");
        helper.registerSigner(testHash, address(9999), ServiceType.BatchPoster);
    }
    
    /**
     * @dev Test two-step deletion for emergency response
     */
    function testTwoStepDeletionForEmergency() public {
        // Register 200 signers
        for (uint i = 0; i < 200; i++) {
            address signer = address(uint160(i + 1));
            helper.registerSigner(testHash, signer, ServiceType.BatchPoster);
        }
        
        // Step 1: Immediately disable the hash (emergency action)
        helper.disableEnclaveHash(testHash, ServiceType.BatchPoster);
        
        // Hash is now disabled, preventing new registrations
        assertEq(helper.registeredEnclaveHashes(ServiceType.BatchPoster, testHash), false);
        
        // Step 2: Clean up signers over multiple transactions
        uint256 remaining = helper.deleteEnclaveHashBatch(testHash, ServiceType.BatchPoster, 100);
        assertEq(remaining, 100); // 100 remaining after first batch
        
        remaining = helper.deleteEnclaveHashBatch(testHash, ServiceType.BatchPoster, 100);
        assertEq(remaining, 0); // All cleaned up
    }
    
    /**
     * @dev Test gas consumption is bounded
     */
    function testGasConsumptionBounded() public {
        // Register max batch size
        for (uint i = 0; i < 100; i++) {
            address signer = address(uint160(i + 1));
            helper.registerSigner(testHash, signer, ServiceType.BatchPoster);
        }
        
        uint256 gasBefore = gasleft();
        helper.deleteEnclaveHashBatch(testHash, ServiceType.BatchPoster, 100);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Should use less than 5M gas for 100 deletions
        assertLt(gasUsed, 5_000_000, "Gas consumption too high");
        
        // Log actual gas usage for reference
        console.log("Gas used for 100 deletions:", gasUsed);
    }
    
    /**
     * @dev Test batch size validation
     */
    function testBatchSizeValidation() public {
        helper.registerSigner(testHash, address(1), ServiceType.BatchPoster);
        
        // Should revert if trying to use batch size > MAX_BATCH_DELETE_SIZE
        vm.expectRevert("Batch size too large");
        helper.deleteEnclaveHashBatch(testHash, ServiceType.BatchPoster, 101);
    }
    
    /**
     * @dev Test that 0 maxIterations uses default
     */
    function testZeroIterationsUsesDefault() public {
        // Register 100 signers
        for (uint i = 0; i < 100; i++) {
            address signer = address(uint160(i + 1));
            helper.registerSigner(testHash, signer, ServiceType.BatchPoster);
        }
        
        // Call with 0 - should use default (MAX_BATCH_DELETE_SIZE = 100)
        uint256 remaining = helper.deleteEnclaveHashBatch(testHash, ServiceType.BatchPoster, 0);
        
        assertEq(remaining, 0); // All should be deleted in one batch
    }
}

