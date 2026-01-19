// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {ITEEVerifier} from "../src/interface/ITEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType} from "../src/types/Types.sol";
import {
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

contract EspressoTEEVerifierTest is Test {
    address adminTEE = address(141);
    address fakeAddress = address(145);

    EspressoTEEVerifier espressoTEEVerifier;
    EspressoSGXTEEVerifier espressoSGXTEEVerifier;
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 enclaveHash =
        bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0);
    //  Address of the automata V3QuoteVerifier deployed on sepolia
    address v3QuoteVerifier = address(0x6E64769A13617f528a2135692484B681Ee1a7169);
    bytes32 pcr0Hash = bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b);

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        // Get the instance of the DCAP Attestation QuoteVerifier on the Arbitrum Sepolia Rollup
        vm.startPrank(adminTEE);

        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(v3QuoteVerifier);
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
            INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );
        espressoSGXTEEVerifier.setEnclaveHash(enclaveHash, true, ServiceType.BatchPoster);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);
        espressoTEEVerifier =
            new EspressoTEEVerifier(espressoSGXTEEVerifier, espressoNitroTEEVerifier);
        vm.stopPrank();
    }

    // This function is intended to be called during test cases to register the caff node.
    // It must be called after `setUp()`, otherwise calls to the individual contracts may not work.
    function registerCaffNodeEnclaveHash() internal {
        vm.startPrank(adminTEE);
        // Register the caff nodes enclave hash
        espressoSGXTEEVerifier.setEnclaveHash(enclaveHash, true, ServiceType.CaffNode);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.CaffNode);
        vm.stopPrank();
    }

    function ensureSeparateCaffNodeOperation(
        bytes memory sampleQuote,
        bytes memory data,
        IEspressoTEEVerifier.TeeType tee,
        bytes4 revertSelector,
        bytes32 revertHash
    ) internal {
        // Test registering the caff node
        // At this point the Caff node enclave hash is not registered so this should fail
        if (tee == IEspressoTEEVerifier.TeeType.NITRO) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ITEEVerifier.InvalidEnclaveHash.selector, pcr0Hash, ServiceType.CaffNode
                )
            );
        } else if (tee == IEspressoTEEVerifier.TeeType.SGX) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ITEEVerifier.InvalidEnclaveHash.selector, enclaveHash, ServiceType.CaffNode
                )
            );
        } // Add more cases here if we support more TEE's
        espressoTEEVerifier.registerService(sampleQuote, data, tee, ServiceType.CaffNode);
        registerCaffNodeEnclaveHash();

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

        vm.startPrank(adminTEE);
        espressoSGXTEEVerifier.setEnclaveHash(enclaveHash, true, ServiceType.CaffNode);
        vm.stopPrank();
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

    function testSGXregisteredSigners() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerService(
            sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );

        assertEq(
            espressoTEEVerifier.registeredSigners(
                batchPosterAddress, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
            ),
            true
        );
        // Assert that this address is not yet registered as a caff node.
        // if the registration process differes between the caff node and the batcher in the
        // future, we will need to update this test.
        assertEq(
            espressoTEEVerifier.registeredSigners(
                batchPosterAddress, IEspressoTEEVerifier.TeeType.SGX, ServiceType.CaffNode
            ),
            false
        );

        ensureSeparateCaffNodeOperation(
            sampleQuote,
            data,
            IEspressoTEEVerifier.TeeType.SGX,
            ITEEVerifier.InvalidEnclaveHash.selector,
            enclaveHash
        );

        assertEq(
            espressoTEEVerifier.registeredSigners(
                batchPosterAddress, IEspressoTEEVerifier.TeeType.SGX, ServiceType.CaffNode
            ),
            true
        );
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

        assertEq(
            espressoTEEVerifier.registeredSigners(
                signerAddr, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
            ),
            true
        );
        // Assert that this address is not yet registered as a caff node.
        // if the registration process differes between the caff node and the batcher in the
        // future, we will need to update this test.
        assertEq(
            espressoTEEVerifier.registeredSigners(
                signerAddr, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
            ),
            false
        );

        ensureSeparateCaffNodeOperation(
            journal,
            onchain,
            IEspressoTEEVerifier.TeeType.NITRO,
            ITEEVerifier.InvalidEnclaveHash.selector,
            pcr0Hash
        );

        assertEq(
            espressoTEEVerifier.registeredSigners(
                signerAddr, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.CaffNode
            ),
            true
        );
    }

    function testSGXRegisteredEnclaveHash() public {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0),
                IEspressoTEEVerifier.TeeType.SGX,
                ServiceType.BatchPoster
            ),
            true
        );
    }

    function testNitroRegisteredEnclaveHash() public {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b),
                IEspressoTEEVerifier.TeeType.NITRO,
                ServiceType.BatchPoster
            ),
            true
        );
    }

    function testSetEspressoSGXTEEVerifier() public {
        vm.startPrank(adminTEE);
        IEspressoSGXTEEVerifier newEspressoSGXTEEVerifier =
            new EspressoSGXTEEVerifier(v3QuoteVerifier);
        espressoTEEVerifier.setEspressoSGXTEEVerifier(newEspressoSGXTEEVerifier);
        assertEq(
            address(espressoTEEVerifier.espressoSGXTEEVerifier()),
            address(newEspressoSGXTEEVerifier)
        );
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoTEEVerifier.setEspressoSGXTEEVerifier(newEspressoSGXTEEVerifier);
        vm.stopPrank();
    }

    function testSetEspressoNitroTEEVerifier() public {
        vm.startPrank(adminTEE);
        IEspressoNitroTEEVerifier newEspressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
            INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788) // Sepolia Nitro Enclave Verifier address
        );
        espressoTEEVerifier.setEspressoNitroTEEVerifier(newEspressoNitroTEEVerifier);
        assertEq(
            address(espressoTEEVerifier.espressoNitroTEEVerifier()),
            address(newEspressoNitroTEEVerifier)
        );
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoTEEVerifier.setEspressoNitroTEEVerifier(newEspressoNitroTEEVerifier);
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
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false, ServiceType.BatchPoster);
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHashes(ServiceType.BatchPoster, pcr0Hash),
            false
        );

        // Expect revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ITEEVerifier.InvalidEnclaveHash.selector, pcr0Hash, ServiceType.BatchPoster
            )
        );
        espressoTEEVerifier.registerService(
            journal, onchain, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );
        vm.stopPrank();
    }

    // Test Ownership transfer using Ownable2Step contract
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

    // Test Address retrieval Nitro
    function testAddressRetrievalNitro() public {
        vm.startPrank(adminTEE);

        // Test without using interface
        address nitroAddr = address(espressoTEEVerifier.espressoNitroTEEVerifier());
        assertEq(address(espressoNitroTEEVerifier), nitroAddr);

        // Test with using EspressoTEEVerifier Interface
        IEspressoTEEVerifier iespressoTEEVerifier =
            new EspressoTEEVerifier(espressoSGXTEEVerifier, espressoNitroTEEVerifier);
        // Without espressoNitroTEEVerifier() added to interface, the test would fail to compile
        nitroAddr = address(iespressoTEEVerifier.espressoNitroTEEVerifier());
        assertEq(address(espressoNitroTEEVerifier), nitroAddr);

        vm.stopPrank();
    }

    // Test Address retrieval SGX
    function testAddressRetrievalSGX() public {
        vm.startPrank(adminTEE);

        // Test without using interface
        address sgxAddr = address(espressoTEEVerifier.espressoSGXTEEVerifier());
        assertEq(address(espressoSGXTEEVerifier), sgxAddr);

        // Test with using EspressoTEEVerifier Interface
        IEspressoTEEVerifier iespressoTEEVerifier =
            new EspressoTEEVerifier(espressoSGXTEEVerifier, espressoNitroTEEVerifier);
        // Without espressoSGXTEEVerifier() added to interface, the test would fail to compile
        sgxAddr = address(iespressoTEEVerifier.espressoSGXTEEVerifier());
        assertEq(address(espressoSGXTEEVerifier), sgxAddr);

        vm.stopPrank();
    }
}
