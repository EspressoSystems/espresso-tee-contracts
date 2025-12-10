// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";

import "@openzeppelin/contracts/access/Ownable.sol";
import {INitroEnclaveVerifier} from
    "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import "./OlympixUnitTest.sol";

contract EspressoTEEVerifierTest is Test, OlympixUnitTest("EspressoTEEVerifier") {
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

        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(enclaveHash, v3QuoteVerifier);
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
            pcr0Hash, INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );
        espressoTEEVerifier =
            new EspressoTEEVerifier(espressoSGXTEEVerifier, espressoNitroTEEVerifier);
        vm.stopPrank();
    }

    function testSGXRegisterSigner() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerSigner(sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX);
    }

    function testNitroRegisterSigner() public {
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");
        espressoTEEVerifier.registerSigner(journal, onchain, IEspressoTEEVerifier.TeeType.NITRO);
    }

    function testSGXRegisterSignerWithInvalidQuote() public {
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoTEEVerifier.registerSigner(sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX);
    }

    function testSGXRegisteredSigners() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerSigner(sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX);

        assertEq(
            espressoTEEVerifier.registeredSigners(
                batchPosterAddress, IEspressoTEEVerifier.TeeType.SGX
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
        espressoTEEVerifier.registerSigner(journal, onchain, IEspressoTEEVerifier.TeeType.NITRO);

        assertEq(
            espressoTEEVerifier.registeredSigners(signerAddr, IEspressoTEEVerifier.TeeType.NITRO),
            true
        );
    }

    function testSGXRegisteredEnclaveHash() public {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0),
                IEspressoTEEVerifier.TeeType.SGX
            ),
            true
        );
    }

    function testNitroRegisteredEnclaveHash() public {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b),
                IEspressoTEEVerifier.TeeType.NITRO
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
        IEspressoNitroTEEVerifier newEspressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
            pcr0Hash,
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
    function testNitroRegisterSignerInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // Disable pcr0 hash
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), false);

        // Expect revert
        vm.expectRevert(IEspressoNitroTEEVerifier.InvalidAWSEnclaveHash.selector);
        espressoTEEVerifier.registerSigner(journal, onchain, IEspressoTEEVerifier.TeeType.NITRO);
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

    function test_verify_nitro_branch_true() public {
        // opix-target-branch-51-True: This test will cause `if (teeType == TeeType.NITRO)` branch in verify() to be taken.
        // To simulate a real ECDSA signature recovery, produce a valid digest and signature for any address.
        // We'll create a local test keypair for reproducibility and sign on chain.
        // We need to register the signer in espressoNitroTEEVerifier or else InvalidSignature will revert.
        // For this test, signature can be arbitrary since we're targeting the NITRO branch and expect revert (branch entered, value is false).

        // Generate private key and signer
        uint256 sk = 0x12341234beef; // test key
        address testSigner = vm.addr(sk);
        // Test message
        bytes32 dummyHash = keccak256("Olympix TEE Test: Nitrogen");
        // Sign the message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, dummyHash);
        bytes memory dummySig = abi.encodePacked(r, s, v);
        IEspressoTEEVerifier.TeeType teeType = IEspressoTEEVerifier.TeeType.NITRO;
        // The underlying espressoNitroTEEVerifier.registeredSigners(testSigner) will return false (not registered), which reverts InvalidSignature.
        vm.expectRevert(IEspressoTEEVerifier.InvalidSignature.selector);
        espressoTEEVerifier.verify(dummySig, dummyHash, teeType);
        // The revert is expected, and the NITRO branch is covered
    }

    function test_registerSigner_else_branch_SGX_coverage() public {
        // Target: Cover the 'else' branch after 'if (teeType == TeeType.SGX)' in registerSigner
        // We make teeType != TeeType.SGX, which means teeType==TeeType.NITRO
        // This covers the required else branch and does not panic or revert on invalid enum values
        // The nested NITRO branch is then hit, but the target 'else' is that after the SGX condition
        // We use dummy data (can be empty bytes)
        bytes memory dummyAttestation = hex"cafebabe";
        bytes memory dummyData = hex"baddad";

        // Since EspressoNitroTEEVerifier expects valid data, it will revert inside that call, which is fine for branch coverage
        vm.expectRevert(); // Accept any revert as we only want to hit the else branch for SGX
        espressoTEEVerifier.registerSigner(
            dummyAttestation, dummyData, IEspressoTEEVerifier.TeeType.NITRO
        );
        // Branch at line if (teeType == TeeType.SGX) is false, else branch is thus covered, and then the call reverts internally
    }

    function test_registerSigner_Nitro_branch_true() public {
        // We want to cover the branch: if (teeType == TeeType.NITRO) {
        // To do this, pass teeType == NITRO to registerSigner().
        // The data passed can be dummy, just needs to be non-empty (could be empty too, if implementation allows).
        // EspressoNitroTEEVerifier is set up in setUp, use it.
        bytes memory dummyJournal = hex"11";
        bytes memory dummyProof = hex"22";
        // Since EspressoNitroTEEVerifier actually expects valid proof, the call will likely revert deeper.
        // But the branch at the top of registerSigner will still be hit for coverage. Expect revert is fine.
        // The revert reason from the implementation may differ, so just use a generic expectRevert.
        vm.expectRevert();
        espressoTEEVerifier.registerSigner(
            dummyJournal, dummyProof, IEspressoTEEVerifier.TeeType.NITRO
        );
        // This branch will be hit, though the revert happens inside espressoNitroTEEVerifier.registerSigner
    }

    function test_registeredSigners_SGX_branch_True() public {
        // We want to hit the branch: if (teeType == TeeType.SGX) { ... }
        // To do this, call registeredSigners() with teeType == SGX, and verify branch is entered.

        address testSigner = address(0xdeadbeef);
        // We need the signer to be registered in underlying espressoSGXTEEVerifier, or at least to call the view.
        // Instead of registering, we can just call registeredSigners on the SGX TEE type to enter the branch; actual return can be false.
        bool ret =
            espressoTEEVerifier.registeredSigners(testSigner, IEspressoTEEVerifier.TeeType.SGX);
        // We expect false since it's not registered, but the point is to cover the branch
        assertEq(ret, espressoSGXTEEVerifier.registeredSigners(testSigner));
    }

    function test_registeredSigners_SGX_if_false_else_branch() public {
        // opix-target-branch-97-YOUR-TEST-SHOULD-ENTER-THIS-ELSE-BRANCH-BY-MAKING-THE-PRECEDING-IFS-CONDITIONS-FALSE
        // To enter the 'else' branch after 'if (teeType == TeeType.SGX)',
        // we must use a TeeType value NOT equal to SGX (which is 0).
        // So use TeeType.NITRO (which is 1), and force the call to go past the first 'if'.
        // We will also construct a dummy signer address.

        address dummySigner = address(0xabcdef);
        // This will enter the else branch of the first 'if', and next check 'if (teeType == TeeType.NITRO)', then return or else continue.
        // For full coverage of the target 97-else branch, what matters is that teeType != SGX, so NITRO suffices.

        // To hit the ELSE branch specifically, we will assert true afterwards.
        // The call will then try to process NITRO branch. To avoid revert (and allow test to run),
        // we assume espressoNitroTEEVerifier exists and can be called. If actual revert is intended for further else branches,
        // that's fine, but for the main target, just calling with NITRO is sufficient.
        // This will test the else branch is covered.

        bool result =
            espressoTEEVerifier.registeredSigners(dummySigner, IEspressoTEEVerifier.TeeType.NITRO);
        // The actual value is irrelevant for branch coverage, but we can assert it matches the underlying verifier
        assertEq(result, espressoNitroTEEVerifier.registeredSigners(dummySigner));
    }
}
