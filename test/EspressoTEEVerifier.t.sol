// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import {ServiceType} from "../src/types/Types.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

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
    bytes32 pcr0Hash = bytes32(0xc980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293);
    bytes nitroPubKey =
        hex"090e39a638094d9805b89a831b7e710db345e701bb0e9865a60b6b50089b3f4b89c168fbf2219ba79b6e86eb63decac3be0dd3e8fb4c0f1b39d4ecd4589704ff";

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        // Get the instance of the DCAP Attestation QuoteVerifier on the Arbitrum Sepolia Rollup
        vm.startPrank(adminTEE);

        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(enclaveHash, v3QuoteVerifier);
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(pcr0Hash, new CertManager());
        espressoTEEVerifier =
            new EspressoTEEVerifier(espressoSGXTEEVerifier, espressoNitroTEEVerifier);
        vm.stopPrank();
    }

    function testSGXRegisterService() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerService(
            sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
    }

    function testNitroRegisterService() public {
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);
        espressoTEEVerifier.registerService(
            attestation, signature, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
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
    }

    function testSGXRegisteredServices() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerService(
            sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );

        assertEq(
            espressoTEEVerifier.registeredServices(
                batchPosterAddress, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
            ),
            true
        );
    }

    function testNitroRegisteredServices() public {
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);
        bytes32 publicKeyHash = keccak256(nitroPubKey);
        address signerAddr = address(uint160(uint256(publicKeyHash)));
        espressoTEEVerifier.registerService(
            attestation, signature, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );

        assertEq(
            espressoTEEVerifier.registeredServices(
                signerAddr, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
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
                bytes32(0xc980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293),
                IEspressoTEEVerifier.TeeType.NITRO,
                ServiceType.BatchPoster
            ),
            true
        );
    }

    function testSetEspressoSGXTEEVerifier() public {
        vm.startPrank(adminTEE);
        IEspressoSGXTEEVerifier newEspressoSGXTEEVerifier =
            new EspressoSGXTEEVerifier(enclaveHash, v3QuoteVerifier);
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
        IEspressoNitroTEEVerifier newEspressoNitroTEEVerifier =
            new EspressoNitroTEEVerifier(pcr0Hash, new CertManager());
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

    function testEspressoNitroTEEVerifySignature() public {
        vm.warp(1_743_620_000);
        // Using attestations where we have a created signature over data
        string memory attestationPath = "/test/configs/nitro-verify-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-verify-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        bytes memory pubKey =
            hex"88195346c675ad5c352ee257ec027c092c995dabd8aa54d2c68f3fac378faf9f402e8eee3418bb434f6feeec541658cd99eec502ace6b145aa2e03ce231ec4e6";
        bytes32 publicKeyHash = keccak256(pubKey);
        address signerAddr = address(uint160(uint256(publicKeyHash)));
        espressoTEEVerifier.registerService(
            attestation, signature, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );

        assertEq(
            espressoTEEVerifier.registeredServices(
                signerAddr, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
            ),
            true
        );

        // Hash and signature which was created sample go code in AWS Nitro Enclave
        bytes32 dataHash =
            bytes32(0xe6e6afefbcd45eac66b314ee8dd955f00cc55de22b504cbf6a0e3fe47715c822);
        bytes memory dataSignature =
            hex"00bdcf15ff1635e99be3dfa38f621ba104ec92e2be97f58c8af3eeacf0cf612c133a6964998903d490bc913ac4217849db5f1f490f6abe0f6814b7336f900ea501";

        // Adjusting ECDSA signature 'v' value for Ethereum compatibility
        // Get `v` from the signature and verify the byte is in expected format for openzeppelin `ECDSA.recover`
        // https://github.com/ethereum/go-ethereum/issues/19751#issuecomment-504900739
        uint8 v = uint8(dataSignature[64]);
        if (v == 0 || v == 1) {
            dataSignature[64] = bytes1(v + 27);
        }
        // Verify we can recover the signer and we are registered
        assertEq(
            espressoTEEVerifier.verify(dataSignature, dataHash, IEspressoTEEVerifier.TeeType.NITRO),
            true
        );

        // invalidate the hash, expect revert
        dataHash = bytes32(0x00e6afefbcd45eac66b314ee8dd955f00cc55de22b504cbf6a0e3fe47715c822);
        vm.expectRevert(IEspressoTEEVerifier.InvalidSignature.selector);
        espressoTEEVerifier.verify(dataSignature, dataHash, IEspressoTEEVerifier.TeeType.NITRO);
    }

    /**
     * Test nitro register signer fails upon invalid attestation pcr0
     */
    function testNitroRegisterServiceInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        // Disable pcr0 hash
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false, ServiceType.BatchPoster);
        assertEq(espressoNitroTEEVerifier.registeredBatchPosterEnclaveHashes(pcr0Hash), false);

        // Expect revert
        vm.expectRevert(IEspressoNitroTEEVerifier.InvalidAWSEnclaveHash.selector);
        espressoTEEVerifier.registerService(
            attestation, signature, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
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
