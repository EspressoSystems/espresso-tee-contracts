// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {
    OwnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {ITEEHelper} from "../src/interface/ITEEHelper.sol";
import {
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

contract EspressoNitroTEEVerifierTest is Test {
    // Owner of the ProxyAdmin contracts that get auto-created by TransparentUpgradeableProxy
    address proxyAdminOwner = address(140);
    address adminTEE = address(141);
    address fakeAddress = address(145);

    EspressoTEEVerifier espressoTEEVerifier;
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 pcr0Hash = bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b);

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/b4eb7cd43eb25061e06a5d07ecd191433c3a28988f14dd9bfb6be6a122355023"
        );
        espressoTEEVerifier = _deployTEEVerifierWithPlaceholders();
        espressoNitroTEEVerifier = _deployNitro(address(espressoTEEVerifier));
        vm.startPrank(adminTEE);
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            IEspressoNitroTEEVerifier(address(espressoNitroTEEVerifier))
        );
        espressoTEEVerifier.setEnclaveHash(pcr0Hash, true, IEspressoTEEVerifier.TeeType.NITRO);
        vm.stopPrank();
    }

    function _deployTEEVerifierWithPlaceholders() internal returns (EspressoTEEVerifier) {
        EspressoTEEVerifier impl = new EspressoTEEVerifier();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            proxyAdminOwner,
            abi.encodeCall(
                EspressoTEEVerifier.initialize,
                (adminTEE, IEspressoNitroTEEVerifier(address(0xBEEF)))
            )
        );
        return EspressoTEEVerifier(address(proxy));
    }

    function _deployNitro(address teeVerifier) internal returns (EspressoNitroTEEVerifier) {
        return new EspressoNitroTEEVerifier(
            teeVerifier, address(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );
    }

    /**
     * Test register signer succeeds upon valid attestation and signature
     */
    function testRegisterBatchPoster() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        espressoNitroTEEVerifier.registerService(output, proofBytes);
        vm.stopPrank();
    }

    /**
     * Test register signer fails upon invalid attestation pcr0
     */
    function testRegisterBatchPosterInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        // Disable pcr0 hash
        espressoTEEVerifier.setEnclaveHash(pcr0Hash, false, IEspressoTEEVerifier.TeeType.NITRO);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), false);

        vm.expectRevert(abi.encodeWithSelector(ITEEHelper.InvalidEnclaveHash.selector, pcr0Hash));
        espressoNitroTEEVerifier.registerService(output, proofBytes);
        vm.stopPrank();
    }

    /**
     * Test invalid proof reverts the transaction
     */
    function testInvalidProof() public {
        vm.startPrank(adminTEE);
        string memory proofPath = "/test/configs/invalid_proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");
        vm.expectRevert();
        espressoNitroTEEVerifier.registerService(output, proofBytes);
        vm.stopPrank();
    }

    /*
     * Test if expired proof reverts
     */
    function testExpiredProof() public {
        vm.startPrank(adminTEE);
        vm.warp(1_433_353_188);
        string memory proofPath = "/test/configs/expired_proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");
        vm.expectRevert();
        espressoNitroTEEVerifier.registerService(output, proofBytes);
        vm.stopPrank();
    }

    // Tee verifier is the admin; non-tee verifier cannot set hashes
    function testSetNitroEnclaveHash() public {
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(pcr0Hash, true, IEspressoTEEVerifier.TeeType.NITRO);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), true);
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(pcr0Hash, false, IEspressoTEEVerifier.TeeType.NITRO);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), false);

        vm.prank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(ITEEHelper.UnauthorizedTEEVerifier.selector, fakeAddress)
        );
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true);
    }

    /**
     * Test we can delete a registered signer with only the correct admin address
     */
    function testDeleteRegisterBatchPosterOwnership() public {
        // register signer
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        // register and verify signer exists
        espressoNitroTEEVerifier.registerService(output, proofBytes);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer));

        // start with incorrect admin address
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = pcr0Hash;

        // verify we cant delete
        vm.expectRevert(
            abi.encodeWithSelector(ITEEHelper.UnauthorizedTEEVerifier.selector, fakeAddress)
        );
        espressoNitroTEEVerifier.deleteEnclaveHashes(enclaveHashes);

        // start with correct admin address
        vm.stopPrank();
        vm.startPrank(adminTEE);

        // delete hash (automatically invalidates signer via isSignerValid)
        espressoTEEVerifier.deleteEnclaveHashes(enclaveHashes, IEspressoTEEVerifier.TeeType.NITRO);

        // Signer is NOT valid (hash deleted, automatic revocation)
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer));
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), false);
    }

    function testDeleteEnclaveHashes() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        espressoNitroTEEVerifier.registerService(output, proofBytes);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        // Verify signer is valid after registration
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer));

        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = pcr0Hash;
        espressoTEEVerifier.deleteEnclaveHashes(enclaveHashes, IEspressoTEEVerifier.TeeType.NITRO);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), false);
        // NOTE: Signers remain in registeredServices (not cleaned to avoid DoS)
        // But isSignerValid() checks if their hash is still approved (automatic revocation!)
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer));
    }

    // Test setting Nitro Enclave Verifier address for tee verifier and non-tee verifier
    function testSetNitroEnclaveVerifierAddress() public {
        vm.startPrank(adminTEE);
        // Use the actual Sepolia Nitro Enclave Verifier address which has deployed code
        address newVerifierAddress = 0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788;
        espressoTEEVerifier.setNitroEnclaveVerifier(newVerifierAddress);
        vm.stopPrank();
        // Check that only tee verifier can set the address
        vm.startPrank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, fakeAddress
            )
        );
        espressoTEEVerifier.setNitroEnclaveVerifier(newVerifierAddress);
        vm.stopPrank();
    }

    function testGuardianCanSetEnclaveHash() public {
        address guardian = address(0x777);

        // Add guardian as owner
        vm.prank(adminTEE);
        espressoTEEVerifier.addGuardian(guardian);

        // Guardian should be able to set enclave hash via TEEVerifier
        bytes32 newHash = bytes32(uint256(55_555));
        vm.prank(guardian);
        espressoTEEVerifier.setEnclaveHash(newHash, true, IEspressoTEEVerifier.TeeType.NITRO);

        // Verify the hash was set
        assertTrue(espressoNitroTEEVerifier.registeredEnclaveHash(newHash));
    }

    function testOwnerCanDeleteEnclaveHashes() public {
        // First set a hash as owner
        bytes32 hashToDelete = bytes32(uint256(44_444));
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(hashToDelete, true, IEspressoTEEVerifier.TeeType.NITRO);

        // Verify it's set
        assertTrue(espressoNitroTEEVerifier.registeredEnclaveHash(hashToDelete));

        // Owner should be able to delete it via TEEVerifier
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = hashToDelete;
        vm.prank(adminTEE);
        espressoTEEVerifier.deleteEnclaveHashes(hashes, IEspressoTEEVerifier.TeeType.NITRO);

        // Verify it's deleted
        assertFalse(espressoNitroTEEVerifier.registeredEnclaveHash(hashToDelete));
    }
}
