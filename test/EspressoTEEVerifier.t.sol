// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {
    IEspressoSGXTEEVerifier
} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {
    IEspressoNitroTEEVerifier
} from "../src/interface/IEspressoNitroTEEVerifier.sol";

import "@openzeppelin/contracts/access/Ownable.sol";
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
        bytes32(
            0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0
        );
    //  Address of the automata V3QuoteVerifier deployed on sepolia
    address v3QuoteVerifier =
        address(0x6E64769A13617f528a2135692484B681Ee1a7169);
    bytes32 pcr0Hash =
        bytes32(
            0x89b2ccf11ff6718a4e015077488f8a98ec11f7c5a14b3a24c3610a7314b680e6
        );

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        // Get the instance of the DCAP Attestation QuoteVerifier on the Arbitrum Sepolia Rollup
        vm.startPrank(adminTEE);

        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(
            enclaveHash,
            v3QuoteVerifier
        );
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
            pcr0Hash,
            INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );
        espressoTEEVerifier = new EspressoTEEVerifier(
            espressoSGXTEEVerifier,
            espressoNitroTEEVerifier
        );
        vm.stopPrank();
    }

    function testSGXRegisterSigner() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(
            0xe2148eE53c0755215Df69b2616E552154EdC584f
        );
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerSigner(
            sampleQuote,
            data,
            IEspressoTEEVerifier.TeeType.SGX
        );
    }

    function testNitroRegisterSigner() public {
        vm.warp(1_743_110_000);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");
        espressoTEEVerifier.registerSigner(
            journal,
            onchain,
            IEspressoTEEVerifier.TeeType.NITRO
        );
    }

    function testSGXRegisterSignerWithInvalidQuote() public {
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(
            0xe2148eE53c0755215Df69b2616E552154EdC584f
        );
        bytes memory data = abi.encodePacked(batchPosterAddress);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoTEEVerifier.registerSigner(
            sampleQuote,
            data,
            IEspressoTEEVerifier.TeeType.SGX
        );
    }

    function testSGXRegisteredSigners() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(
            0xe2148eE53c0755215Df69b2616E552154EdC584f
        );
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerSigner(
            sampleQuote,
            data,
            IEspressoTEEVerifier.TeeType.SGX
        );

        assertEq(
            espressoTEEVerifier.registeredSigners(
                batchPosterAddress,
                IEspressoTEEVerifier.TeeType.SGX
            ),
            true
        );
    }

    function testNitroRegisteredSigners() public {
        vm.warp(1_743_110_000);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");
        address signerAddr = 0x1b76eaFc1f9dD32D42518F08B3059D7fb32636AC;
        espressoTEEVerifier.registerSigner(
            journal,
            onchain,
            IEspressoTEEVerifier.TeeType.NITRO
        );

        assertEq(
            espressoTEEVerifier.registeredSigners(
                signerAddr,
                IEspressoTEEVerifier.TeeType.NITRO
            ),
            true
        );
    }

    function testSGXRegisteredEnclaveHash() public {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(
                    0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0
                ),
                IEspressoTEEVerifier.TeeType.SGX
            ),
            true
        );
    }

    function testNitroRegisteredEnclaveHash() public {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(
                    0x89b2ccf11ff6718a4e015077488f8a98ec11f7c5a14b3a24c3610a7314b680e6
                ),
                IEspressoTEEVerifier.TeeType.NITRO
            ),
            true
        );
    }

    function testSetEspressoSGXTEEVerifier() public {
        vm.startPrank(adminTEE);
        IEspressoSGXTEEVerifier newEspressoSGXTEEVerifier = new EspressoSGXTEEVerifier(
                enclaveHash,
                v3QuoteVerifier
            );
        espressoTEEVerifier.setEspressoSGXTEEVerifier(
            newEspressoSGXTEEVerifier
        );
        assertEq(
            address(espressoTEEVerifier.espressoSGXTEEVerifier()),
            address(newEspressoSGXTEEVerifier)
        );
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoTEEVerifier.setEspressoSGXTEEVerifier(
            newEspressoSGXTEEVerifier
        );
        vm.stopPrank();
    }

    function testSetEspressoNitroTEEVerifier() public {
        vm.startPrank(adminTEE);
        IEspressoNitroTEEVerifier newEspressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
                pcr0Hash,
                INitroEnclaveVerifier(
                    0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788
                ) // Sepolia Nitro Enclave Verifier address
            );
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            newEspressoNitroTEEVerifier
        );
        assertEq(
            address(espressoTEEVerifier.espressoNitroTEEVerifier()),
            address(newEspressoNitroTEEVerifier)
        );
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            newEspressoNitroTEEVerifier
        );
        vm.stopPrank();
    }

    /**
     * Test nitro register signer fails upon invalid attestation pcr0
     */
    function testNitroRegisterSignerInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_743_110_000);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // Disable pcr0 hash
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false);
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash),
            false
        );

        // Expect revert
        vm.expectRevert(
            IEspressoNitroTEEVerifier.InvalidAWSEnclaveHash.selector
        );
        espressoTEEVerifier.registerSigner(
            journal,
            onchain,
            IEspressoTEEVerifier.TeeType.NITRO
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
        address nitroAddr = address(
            espressoTEEVerifier.espressoNitroTEEVerifier()
        );
        assertEq(address(espressoNitroTEEVerifier), nitroAddr);

        // Test with using EspressoTEEVerifier Interface
        IEspressoTEEVerifier iespressoTEEVerifier = new EspressoTEEVerifier(
            espressoSGXTEEVerifier,
            espressoNitroTEEVerifier
        );
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
        IEspressoTEEVerifier iespressoTEEVerifier = new EspressoTEEVerifier(
            espressoSGXTEEVerifier,
            espressoNitroTEEVerifier
        );
        // Without espressoSGXTEEVerifier() added to interface, the test would fail to compile
        sgxAddr = address(iespressoTEEVerifier.espressoSGXTEEVerifier());
        assertEq(address(espressoSGXTEEVerifier), sgxAddr);

        vm.stopPrank();
    }
}
