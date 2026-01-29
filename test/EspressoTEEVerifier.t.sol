// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {
    OwnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {OwnableWithGuardiansUpgradeable} from "../src/OwnableWithGuardiansUpgradeable.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {ITEEHelper} from "../src/interface/ITEEHelper.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType} from "../src/types/Types.sol";
import {
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

contract EspressoTEEVerifierTest is Test {
    address adminTEE = address(141);
    address fakeAddress = address(145);
    // Owner of the ProxyAdmin contracts that get auto-created by TransparentUpgradeableProxy
    address proxyAdminOwner = address(140);

    EspressoTEEVerifier espressoTEEVerifier;
    EspressoSGXTEEVerifier espressoSGXTEEVerifier;
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 enclaveHash =
        bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0);
    //  Address of the automata V3QuoteVerifier deployed on sepolia
    address v3QuoteVerifier = address(0x6E64769A13617f528a2135692484B681Ee1a7169);
    bytes32 pcr0Hash = bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b);

    function _deploySGX(address teeVerifier) internal returns (EspressoSGXTEEVerifier) {
        EspressoSGXTEEVerifier impl = new EspressoSGXTEEVerifier();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            proxyAdminOwner,
            abi.encodeCall(EspressoSGXTEEVerifier.initialize, (teeVerifier, v3QuoteVerifier))
        );
        return EspressoSGXTEEVerifier(address(proxy));
    }

    function _deployNitro(address teeVerifier) internal returns (EspressoNitroTEEVerifier) {
        EspressoNitroTEEVerifier impl = new EspressoNitroTEEVerifier();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            proxyAdminOwner,
            abi.encodeCall(
                EspressoNitroTEEVerifier.initialize,
                (teeVerifier, INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788))
            )
        );
        return EspressoNitroTEEVerifier(address(proxy));
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

    function setUp() public {
        vm.stopPrank();
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        espressoTEEVerifier = _deployTEEVerifierWithPlaceholders();
        espressoSGXTEEVerifier = _deploySGX(address(espressoTEEVerifier));
        espressoNitroTEEVerifier = _deployNitro(address(espressoTEEVerifier));

        // Wire the tee verifier to the freshly deployed helpers and seed enclave hashes.
        vm.startPrank(adminTEE);
        espressoTEEVerifier.setEspressoSGXTEEVerifier(
            IEspressoSGXTEEVerifier(address(espressoSGXTEEVerifier))
        );
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            IEspressoNitroTEEVerifier(address(espressoNitroTEEVerifier))
        );
        espressoTEEVerifier.setEnclaveHash(
            enclaveHash, true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        espressoTEEVerifier.setEnclaveHash(
            enclaveHash, true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.CaffNode
        );
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, true, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, true, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
        );
        vm.stopPrank();
    }

    // Helper to toggle the caff node enclave hash for different TEEs during tests.
    function setCaffNodeEnclaveHash(IEspressoTEEVerifier.TeeType tee, bytes32 hash, bool valid)
        internal
    {
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(hash, valid, tee, ServiceType.CaffNode);
    }

    function ensureSeparateCaffNodeOperation(
        bytes memory sampleQuote,
        bytes memory data,
        IEspressoTEEVerifier.TeeType tee,
        bytes32 revertHash
    ) internal {
        // Test registering the caff node
        // At this point the Caff node enclave hash is not registered so this should fail
        setCaffNodeEnclaveHash(tee, revertHash, false);
        if (tee == IEspressoTEEVerifier.TeeType.NITRO) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ITEEHelper.InvalidEnclaveHash.selector, pcr0Hash, ServiceType.CaffNode
                )
            );
        } else if (tee == IEspressoTEEVerifier.TeeType.SGX) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ITEEHelper.InvalidEnclaveHash.selector, enclaveHash, ServiceType.CaffNode
                )
            );
        } // Add more cases here if we support more TEE's
        espressoTEEVerifier.registerService(sampleQuote, data, tee, ServiceType.CaffNode);
        setCaffNodeEnclaveHash(tee, revertHash, true);

        // At this point the Caff node enclave hash is registered so this should succeed
        espressoTEEVerifier.registerService(sampleQuote, data, tee, ServiceType.CaffNode);
    }

    function testSGXRegisterService() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        // Test registering the batch poster
        espressoTEEVerifier.registerService(
            sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );

        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            enclaveHash, true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.CaffNode
        );
        espressoTEEVerifier.registerService(
            sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.CaffNode
        );
    }

    function testNitroRegisterService() public {
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");
        espressoTEEVerifier.registerService(
            journal, onchain, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
    }

    function testSGXRegisterServiceWithInvalidQuote() public {
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoTEEVerifier.registerService(
            sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        // Test registering the caff node as well, this should fail with an invalid quote.
        // This would also fail with an invalid enclave hash as well, as this test doesn't register the caff node,
        // But that isn't needed for this test.
        espressoTEEVerifier.registerService(
            sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.CaffNode
        );
    }

    function testSGXRegisteredSigners() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerService(
            sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );

        assertTrue(
            espressoSGXTEEVerifier.isSignerValid(batchPosterAddress, ServiceType.BatchPoster)
        );
        // Assert that this address is not yet registered as a caff node.
        // if the registration process differs between the caff node and the batcher in the
        // future, we will need to update this test.
        assertFalse(espressoSGXTEEVerifier.isSignerValid(batchPosterAddress, ServiceType.CaffNode));

        ensureSeparateCaffNodeOperation(
            sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX, enclaveHash
        );

        assertTrue(espressoSGXTEEVerifier.isSignerValid(batchPosterAddress, ServiceType.CaffNode));
    }

    function testNitroRegisteredSigners() public {
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");
        address signerAddr = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        espressoTEEVerifier.registerService(
            journal, onchain, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );

        assertTrue(espressoNitroTEEVerifier.isSignerValid(signerAddr, ServiceType.BatchPoster));
        // Assert that this address is not yet registered as a caff node.
        // if the registration process differs between the caff node and the batcher in the
        // future, we will need to update this test.
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signerAddr, ServiceType.CaffNode));

        ensureSeparateCaffNodeOperation(
            journal, onchain, IEspressoTEEVerifier.TeeType.NITRO, pcr0Hash
        );

        assertTrue(espressoNitroTEEVerifier.isSignerValid(signerAddr, ServiceType.CaffNode));
    }

    function testSGXRegisteredEnclaveHash() public view {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0),
                IEspressoTEEVerifier.TeeType.SGX,
                ServiceType.BatchPoster
            ),
            true
        );

        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0),
                IEspressoTEEVerifier.TeeType.SGX,
                ServiceType.CaffNode
            ),
            true
        );
    }

    function testNitroRegisteredEnclaveHash() public view {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b),
                IEspressoTEEVerifier.TeeType.NITRO,
                ServiceType.BatchPoster
            ),
            true
        );
    }

    function testDeleteEnclaveHashesSGX() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        espressoTEEVerifier.registerService(
            sampleQuote,
            abi.encodePacked(batchPosterAddress),
            IEspressoTEEVerifier.TeeType.SGX,
            ServiceType.BatchPoster
        );

        // Verify signer is valid after registration
        assertTrue(
            espressoSGXTEEVerifier.isSignerValid(batchPosterAddress, ServiceType.BatchPoster)
        );

        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = enclaveHash;
        espressoTEEVerifier.deleteEnclaveHashes(
            enclaveHashes, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                enclaveHash, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
            ),
            false
        );
        // NOTE: Signers remain in internal mapping (not cleaned to avoid DoS)
        // But signer is automatically invalid (hash was deleted)
        assertFalse(
            espressoSGXTEEVerifier.isSignerValid(batchPosterAddress, ServiceType.BatchPoster)
        );
        vm.stopPrank();
    }

    function testDeleteEnclaveHashesNitro() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        espressoTEEVerifier.registerService(
            output, proofBytes, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        // Verify signer is valid after registration
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));

        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = pcr0Hash;
        espressoTEEVerifier.deleteEnclaveHashes(
            enclaveHashes, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                pcr0Hash, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
            ),
            false
        );
        // NOTE: Signers remain in internal mapping (not cleaned to avoid DoS)
        // But signer is automatically invalid (hash was deleted)
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));
        vm.stopPrank();
    }

    function testSetEspressoSGXTEEVerifier() public {
        EspressoSGXTEEVerifier newEspressoSGXTEEVerifier = _deploySGX(address(espressoTEEVerifier));
        vm.startPrank(adminTEE);
        espressoTEEVerifier.setEspressoSGXTEEVerifier(
            IEspressoSGXTEEVerifier(address(newEspressoSGXTEEVerifier))
        );
        assertEq(
            address(espressoTEEVerifier.espressoSGXTEEVerifier()),
            address(newEspressoSGXTEEVerifier)
        );
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, fakeAddress
            )
        );
        espressoTEEVerifier.setEspressoSGXTEEVerifier(
            IEspressoSGXTEEVerifier(address(newEspressoSGXTEEVerifier))
        );
        vm.stopPrank();
    }

    function testSetEspressoNitroTEEVerifier() public {
        EspressoNitroTEEVerifier newEspressoNitroTEEVerifier =
            _deployNitro(address(espressoTEEVerifier));
        vm.startPrank(adminTEE);
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            IEspressoNitroTEEVerifier(address(newEspressoNitroTEEVerifier))
        );
        assertEq(
            address(espressoTEEVerifier.espressoNitroTEEVerifier()),
            address(newEspressoNitroTEEVerifier)
        );
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, fakeAddress
            )
        );
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            IEspressoNitroTEEVerifier(address(newEspressoNitroTEEVerifier))
        );
        vm.stopPrank();
    }

    /**
     * Test nitro register signer fails upon invalid attestation pcr0
     */
    function testNitroRegisterServiceInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // Disable pcr0 hash
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash, false, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash, ServiceType.BatchPoster), false
        );

        // Expect revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ITEEHelper.InvalidEnclaveHash.selector, pcr0Hash, ServiceType.BatchPoster
            )
        );
        espressoTEEVerifier.registerService(
            journal, onchain, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        vm.stopPrank();
    }

    function testOwnerOnlyAdminPassthroughs() public {
        vm.startPrank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableWithGuardiansUpgradeable.NotGuardianOrOwner.selector, fakeAddress
            )
        );
        espressoTEEVerifier.setEnclaveHash(
            bytes32(uint256(123)), true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableWithGuardiansUpgradeable.NotGuardianOrOwner.selector, fakeAddress
            )
        );
        bytes32[] memory hashes = new bytes32[](1);
        espressoTEEVerifier.deleteEnclaveHashes(
            hashes, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, fakeAddress
            )
        );
        espressoTEEVerifier.setQuoteVerifier(address(0xABCD));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, fakeAddress
            )
        );
        espressoTEEVerifier.setNitroEnclaveVerifier(address(0xABCD));
        vm.stopPrank();
    }

    function testSetEnclaveHashAndDelete() public {
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            bytes32(uint256(999)), true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        assertTrue(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(uint256(999)), IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
            )
        );
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = bytes32(uint256(999));
        vm.prank(adminTEE);
        espressoTEEVerifier.deleteEnclaveHashes(
            hashes, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        assertFalse(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(uint256(999)), IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
            )
        );
    }

    function testSetQuoteAndNitroVerifiers() public {
        vm.prank(adminTEE);
        espressoTEEVerifier.setQuoteVerifier(address(espressoSGXTEEVerifier));
        assertEq(address(espressoSGXTEEVerifier.quoteVerifier()), address(espressoSGXTEEVerifier));

        vm.prank(adminTEE);
        espressoTEEVerifier.setNitroEnclaveVerifier(address(espressoNitroTEEVerifier));
        assertEq(
            address(espressoNitroTEEVerifier.nitroEnclaveVerifier()),
            address(espressoNitroTEEVerifier)
        );
    }

    function testOwnershipTransfer() public {
        vm.startPrank(adminTEE);
        assertEq(address(espressoTEEVerifier.owner()), adminTEE);
        espressoTEEVerifier.transferOwnership(fakeAddress);
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        espressoTEEVerifier.acceptOwnership();
        assertEq(address(espressoTEEVerifier.owner()), fakeAddress);
        vm.stopPrank();
    }

    function testAddressRetrievalNitro() public {
        vm.startPrank(adminTEE);

        // Test without using interface
        address nitroAddr = address(espressoTEEVerifier.espressoNitroTEEVerifier());
        assertEq(address(espressoNitroTEEVerifier), nitroAddr);
        vm.stopPrank();
    }

    function testAddressRetrievalSGX() public {
        vm.startPrank(adminTEE);

        address sgxAddr = address(espressoTEEVerifier.espressoSGXTEEVerifier());
        assertEq(address(espressoSGXTEEVerifier), sgxAddr);
        vm.stopPrank();
    }

    function testGuardianCanSetEnclaveHashSGX() public {
        address guardian = address(0x999);
        
        // Add guardian as owner
        vm.prank(adminTEE);
        espressoTEEVerifier.addGuardian(guardian);
        
        // Guardian should be able to set enclave hash
        bytes32 newHash = bytes32(uint256(12345));
        vm.prank(guardian);
        espressoTEEVerifier.setEnclaveHash(
            newHash, true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        
        // Verify the hash was set
        assertTrue(
            espressoTEEVerifier.registeredEnclaveHashes(
                newHash, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
            )
        );
    }

    function testGuardianCanSetEnclaveHashNitro() public {
        address guardian = address(0x999);
        
        // Add guardian as owner
        vm.prank(adminTEE);
        espressoTEEVerifier.addGuardian(guardian);
        
        // Guardian should be able to set enclave hash
        bytes32 newHash = bytes32(uint256(54321));
        vm.prank(guardian);
        espressoTEEVerifier.setEnclaveHash(
            newHash, true, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
        );
        
        // Verify the hash was set
        assertTrue(
            espressoTEEVerifier.registeredEnclaveHashes(
                newHash, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
            )
        );
    }

    function testGuardianCanDeleteEnclaveHashesSGX() public {
        address guardian = address(0x999);
        
        // Add guardian as owner
        vm.prank(adminTEE);
        espressoTEEVerifier.addGuardian(guardian);
        
        // First set a hash as owner
        bytes32 hashToDelete = bytes32(uint256(99999));
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            hashToDelete, true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        
        // Verify it's set
        assertTrue(
            espressoTEEVerifier.registeredEnclaveHashes(
                hashToDelete, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
            )
        );
        
        // Guardian should be able to delete it
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = hashToDelete;
        vm.prank(guardian);
        espressoTEEVerifier.deleteEnclaveHashes(
            hashes, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        
        // Verify it's deleted
        assertFalse(
            espressoTEEVerifier.registeredEnclaveHashes(
                hashToDelete, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
            )
        );
    }

    function testGuardianCanDeleteEnclaveHashesNitro() public {
        address guardian = address(0x999);
        
        // Add guardian as owner
        vm.prank(adminTEE);
        espressoTEEVerifier.addGuardian(guardian);
        
        // First set a hash as owner
        bytes32 hashToDelete = bytes32(uint256(88888));
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            hashToDelete, true, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
        );
        
        // Verify it's set
        assertTrue(
            espressoTEEVerifier.registeredEnclaveHashes(
                hashToDelete, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
            )
        );
        
        // Guardian should be able to delete it
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = hashToDelete;
        vm.prank(guardian);
        espressoTEEVerifier.deleteEnclaveHashes(
            hashes, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
        );
        
        // Verify it's deleted
        assertFalse(
            espressoTEEVerifier.registeredEnclaveHashes(
                hashToDelete, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
            )
        );
    }
}
