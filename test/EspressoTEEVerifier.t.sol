// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {OwnableWithGuardiansUpgradeable} from "../src/OwnableWithGuardiansUpgradeable.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {ITEEHelper} from "../src/interface/ITEEHelper.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {INitroEnclaveVerifier} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

contract EspressoTEEVerifierTest is Test {
    address adminTEE = address(141);
    address fakeAddress = address(145);
    // Owner of the ProxyAdmin contracts that get auto-created by TransparentUpgradeableProxy
    address proxyAdminOwner = address(140);

    EspressoTEEVerifier espressoTEEVerifier;
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 pcr0Hash =
        bytes32(
            0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b
        );

    function _deployNitro(
        address teeVerifier
    ) internal returns (EspressoNitroTEEVerifier) {
        return
            new EspressoNitroTEEVerifier(
                teeVerifier,
                address(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
            );
    }

    function _deployTEEVerifierWithPlaceholders()
        internal
        returns (EspressoTEEVerifier)
    {
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

    function setUp() public {
        vm.stopPrank();
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/b4eb7cd43eb25061e06a5d07ecd191433c3a28988f14dd9bfb6be6a122355023"
        );
        espressoTEEVerifier = _deployTEEVerifierWithPlaceholders();
        espressoNitroTEEVerifier = _deployNitro(address(espressoTEEVerifier));

        // Wire the tee verifier to the freshly deployed helpers and seed enclave hashes.
        vm.startPrank(adminTEE);
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            IEspressoNitroTEEVerifier(address(espressoNitroTEEVerifier))
        );
        espressoTEEVerifier.setEnclaveHash(
            pcr0Hash,
            true,
            IEspressoTEEVerifier.TeeType.NITRO
        );
        vm.stopPrank();
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
            journal,
            onchain,
            IEspressoTEEVerifier.TeeType.NITRO
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
            journal,
            onchain,
            IEspressoTEEVerifier.TeeType.NITRO
        );

        assertTrue(espressoNitroTEEVerifier.isSignerValid(signerAddr));
    }

    function testNitroRegisteredEnclaveHash() public view {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(
                    0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b
                ),
                IEspressoTEEVerifier.TeeType.NITRO
            ),
            true
        );
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
            output,
            proofBytes,
            IEspressoTEEVerifier.TeeType.NITRO
        );

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        // Verify signer is valid after registration
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer));

        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = pcr0Hash;
        espressoTEEVerifier.deleteEnclaveHashes(
            enclaveHashes,
            IEspressoTEEVerifier.TeeType.NITRO
        );
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                pcr0Hash,
                IEspressoTEEVerifier.TeeType.NITRO
            ),
            false
        );
        // NOTE: Signers remain in internal mapping (not cleaned to avoid DoS)
        // But signer is automatically invalid (hash was deleted)
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer));
        vm.stopPrank();
    }

    function testSetEspressoNitroTEEVerifier() public {
        EspressoNitroTEEVerifier newEspressoNitroTEEVerifier = _deployNitro(
            address(espressoTEEVerifier)
        );
        address oldVerifier = address(
            espressoTEEVerifier.espressoNitroTEEVerifier()
        );
        vm.startPrank(adminTEE);
        vm.expectEmit(true, true, false, false, address(espressoTEEVerifier));
        emit IEspressoTEEVerifier.EspressoNitroTEEVerifierSet(
            oldVerifier,
            address(newEspressoNitroTEEVerifier)
        );
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
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                fakeAddress
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
            pcr0Hash,
            false,
            IEspressoTEEVerifier.TeeType.NITRO
        );
        assertEq(
            espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash),
            false
        );

        // Expect revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ITEEHelper.InvalidEnclaveHash.selector,
                pcr0Hash
            )
        );
        espressoTEEVerifier.registerService(
            journal,
            onchain,
            IEspressoTEEVerifier.TeeType.NITRO
        );
        vm.stopPrank();
    }

    function testOwnerOnlyAdminPassthroughs() public {
        vm.startPrank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableWithGuardiansUpgradeable.NotGuardianOrOwner.selector,
                fakeAddress
            )
        );
        espressoTEEVerifier.setEnclaveHash(
            bytes32(uint256(123)),
            true,
            IEspressoTEEVerifier.TeeType.NITRO
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                fakeAddress
            )
        );
        bytes32[] memory hashes = new bytes32[](1);
        espressoTEEVerifier.deleteEnclaveHashes(
            hashes,
            IEspressoTEEVerifier.TeeType.NITRO
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                fakeAddress
            )
        );
        espressoTEEVerifier.setNitroEnclaveVerifier(address(0xABCD));
        vm.stopPrank();
    }

    function testSetEnclaveHashAndDelete() public {
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            bytes32(uint256(999)),
            true,
            IEspressoTEEVerifier.TeeType.NITRO
        );
        assertTrue(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(uint256(999)),
                IEspressoTEEVerifier.TeeType.NITRO
            )
        );
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = bytes32(uint256(999));
        vm.prank(adminTEE);
        espressoTEEVerifier.deleteEnclaveHashes(
            hashes,
            IEspressoTEEVerifier.TeeType.NITRO
        );
        assertFalse(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(uint256(999)),
                IEspressoTEEVerifier.TeeType.NITRO
            )
        );
    }

    function testSetNitroVerifier() public {
        vm.prank(adminTEE);
        espressoTEEVerifier.setNitroEnclaveVerifier(
            address(espressoNitroTEEVerifier)
        );
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
        address nitroAddr = address(
            espressoTEEVerifier.espressoNitroTEEVerifier()
        );
        assertEq(address(espressoNitroTEEVerifier), nitroAddr);
        vm.stopPrank();
    }

    function testGuardianCanSetEnclaveHashNitro() public {
        address guardian = address(0x999);

        // Add guardian as owner
        vm.prank(adminTEE);
        espressoTEEVerifier.addGuardian(guardian);

        // Guardian should be able to set enclave hash
        bytes32 newHash = bytes32(uint256(54_321));
        vm.prank(guardian);
        espressoTEEVerifier.setEnclaveHash(
            newHash,
            true,
            IEspressoTEEVerifier.TeeType.NITRO
        );

        // Verify the hash was set
        assertTrue(
            espressoTEEVerifier.registeredEnclaveHashes(
                newHash,
                IEspressoTEEVerifier.TeeType.NITRO
            )
        );
    }

    function testOwnerCanDeleteEnclaveHashesNitro() public {
        // First set a hash as owner
        bytes32 hashToDelete = bytes32(uint256(88_888));
        vm.prank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            hashToDelete,
            true,
            IEspressoTEEVerifier.TeeType.NITRO
        );

        // Verify it's set
        assertTrue(
            espressoTEEVerifier.registeredEnclaveHashes(
                hashToDelete,
                IEspressoTEEVerifier.TeeType.NITRO
            )
        );

        // Owner should be able to delete it
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = hashToDelete;
        vm.prank(adminTEE);
        espressoTEEVerifier.deleteEnclaveHashes(
            hashes,
            IEspressoTEEVerifier.TeeType.NITRO
        );

        // Verify it's deleted
        assertFalse(
            espressoTEEVerifier.registeredEnclaveHashes(
                hashToDelete,
                IEspressoTEEVerifier.TeeType.NITRO
            )
        );
    }

    function testVerifyWithEIP712() public {
        uint256 signerPk = 0x1;
        address signerAddr = vm.addr(signerPk);

        // Mock isSignerValid on NitroVerifier
        vm.mockCall(
            address(espressoNitroTEEVerifier),
            abi.encodeWithSelector(
                ITEEHelper.isSignerValid.selector,
                signerAddr
            ),
            abi.encode(true)
        );

        bytes32 typeHash = keccak256("EspressoTEEVerifier(bytes32 commitment)");

        bytes32 userDataHash = keccak256("test data");
        bytes32 structHash = keccak256(abi.encode(typeHash, userDataHash));

        // Reconstruct EIP-712 domain separator
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("EspressoTEEVerifier"),
                keccak256("1"),
                block.chainid,
                address(espressoTEEVerifier)
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        // Sign the digest with the signer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Call verify as the caller
        vm.prank(signerAddr);
        bool result = espressoTEEVerifier.verify(
            signature,
            userDataHash,
            IEspressoTEEVerifier.TeeType.NITRO
        );
        assertTrue(result);

        // Test signature without EIP712 should revert

        vm.prank(signerAddr);
        bytes32 emptyDomainSeparator = bytes32(0);
        digest = keccak256(
            abi.encodePacked("\x19\x01", emptyDomainSeparator, structHash)
        );
        (v, r, s) = vm.sign(signerPk, digest);
        signature = abi.encodePacked(r, s, v);

        vm.expectRevert(IEspressoTEEVerifier.InvalidSignature.selector);
        espressoTEEVerifier.verify(
            signature,
            userDataHash,
            IEspressoTEEVerifier.TeeType.NITRO
        );
    }
}
