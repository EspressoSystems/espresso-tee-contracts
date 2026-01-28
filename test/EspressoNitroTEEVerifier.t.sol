// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {
    OwnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {ITEEHelper} from "../src/interface/ITEEHelper.sol";
import {ServiceType} from "../src/types/Types.sol";
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
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        espressoTEEVerifier = _deployTEEVerifierWithPlaceholders();
        espressoNitroTEEVerifier = _deployNitro(address(espressoTEEVerifier));
        vm.startPrank(adminTEE);
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            IEspressoNitroTEEVerifier(address(espressoNitroTEEVerifier))
        );
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, true, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, true, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
        );
        vm.stopPrank();
    }

    function _deployTEEVerifierWithPlaceholders() internal returns (EspressoTEEVerifier) {
        EspressoTEEVerifier impl = new EspressoTEEVerifier();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            proxyAdminOwner,
            abi.encodeCall(
                EspressoTEEVerifier.initialize,
                (
                    adminTEE,
                    IEspressoSGXTEEVerifier(address(0xDEAD)),
                    IEspressoNitroTEEVerifier(address(0xBEEF))
                )
            )
        );
        return EspressoTEEVerifier(address(proxy));
    }

    function _deployNitro(address teeVerifier) internal returns (EspressoNitroTEEVerifier) {
        EspressoNitroTEEVerifier impl = new EspressoNitroTEEVerifier();
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(impl), proxyAdminOwner, "");
        EspressoNitroTEEVerifier proxied = EspressoNitroTEEVerifier(address(proxy));
        vm.prank(teeVerifier);
        proxied.initialize(
            teeVerifier,
            INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788) // Sepolia Nitro Enclave Verifier address
        );
        return proxied;
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

        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);
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
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, false, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash, ServiceType.BatchPoster), false
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ITEEHelper.InvalidEnclaveHash.selector, pcr0Hash, ServiceType.BatchPoster
            )
        );
        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);
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
        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);
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
        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);
        vm.stopPrank();
    }

    // Tee verifier is the admin; non-tee verifier cannot set hashes
    function testSetNitroEnclaveHash() public {
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, true, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash, ServiceType.BatchPoster), true
        );
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, false, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash, ServiceType.BatchPoster), false
        );

        vm.prank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(ITEEHelper.UnauthorizedTEEVerifier.selector, fakeAddress)
        );
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);

        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, true, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
        );
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash, ServiceType.CaffNode), true
        );
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, false, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
        );
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash, ServiceType.CaffNode), false
        );
        vm.prank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(ITEEHelper.UnauthorizedTEEVerifier.selector, fakeAddress)
        );
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.CaffNode);
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
        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));

        // start with incorrect admin address
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = pcr0Hash;

        // verify we cant delete
        vm.expectRevert(
            abi.encodeWithSelector(ITEEHelper.UnauthorizedTEEVerifier.selector, fakeAddress)
        );
        espressoNitroTEEVerifier.deleteEnclaveHashes(enclaveHashes, ServiceType.BatchPoster);

        // start with correct admin address
        vm.stopPrank();
        vm.startPrank(adminTEE);

        // delete hash (automatically invalidates signer via isSignerValid)
        espressoTEEVerifier.deleteEnclaveHashes(
            enclaveHashes, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );

        // Signer is NOT valid (hash deleted, automatic revocation)
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash, ServiceType.BatchPoster), false
        );
    }

    // Test we can delete a registered caff node with only the correct admin address
    function testDeleteRegisterCaffNodeOwnership() public {
        // register signer
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // register and verify signer exists
        espressoNitroTEEVerifier.registerService(journal, onchain, ServiceType.CaffNode);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.CaffNode));

        // delete hash (automatically invalidates signer via isSignerValid)
        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = pcr0Hash;
        espressoTEEVerifier.deleteEnclaveHashes(
            enclaveHashes, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
        );

        // Signer is NOT valid (hash deleted, automatic revocation)
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.CaffNode));
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash, ServiceType.CaffNode), false
        );
    }

    function testEnclaveHashSignersAndDeleteEnclaveHashes() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        address[] memory signers =
            espressoNitroTEEVerifier.enclaveHashSigners(pcr0Hash, ServiceType.BatchPoster);
        assertEq(signers.length, 1);
        assertEq(signers[0], signer);

        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = pcr0Hash;
        espressoTEEVerifier.deleteEnclaveHashes(
            enclaveHashes, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash, ServiceType.BatchPoster), false
        );
        // NOTE: Signers remain in registeredServices (not cleaned to avoid DoS)
        // But isSignerValid() checks if their hash is still approved (automatic revocation!)
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));

        address[] memory signersAfter =
            espressoNitroTEEVerifier.enclaveHashSigners(pcr0Hash, ServiceType.BatchPoster);
        // Signers remain in enclaveHashToSigner set (not cleaned to avoid DoS)
        assertEq(signersAfter.length, 1);
    }

    // Test setting Nitro Enclave Verifier address for tee verifier and non-tee verifier
    function testSetNitroEnclaveVerifierAddress() public {
        vm.startPrank(adminTEE);
        address newVerifierAddress = 0x1234567890123456789012345678901234567890;
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

    function testInitializeCannotRunTwice() public {
        vm.prank(adminTEE);
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        espressoNitroTEEVerifier.initialize(
            adminTEE, INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );
    }
}
