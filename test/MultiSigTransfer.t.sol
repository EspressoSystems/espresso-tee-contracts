// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {INitroEnclaveVerifier} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";

import {MultiSigTransfer} from "../scripts/MultiSigTransfer.s.sol";

contract MultiSigTransferTest is Test {
    // declare addresses for the test
    address originalOwner = address(999); // address value: 0x00000000000000000000000000000000000003e7
    address newOwner = address(145); // address value: 0x0000000000000000000000000000000000000091
    address badNewOwner = address(146); // address value: 0x0000000000000000000000000000000000000092

    // string representations of addresses for vm.setEnv.
    string originalOwnerString = "0x00000000000000000000000000000000000003e7";
    string newOwnerString = "0x0000000000000000000000000000000000000091";
    string badNewOwnerString = "0x0000000000000000000000000000000000000092";

    // Get the bytes values of the addresses so we can set env vars for the tests.
    bytes originalOwnerBytes = abi.encodePacked(originalOwner);
    bytes newOwnerBytes = abi.encodePacked(newOwner);
    bytes badNewOwnerBytes = abi.encodePacked(badNewOwner);
    // Env var constants used by ownership transfer script.
    string constant newOwnerEnv = "MULTISIG_CONTRACT_ADDRESS";
    string constant teeVerifierEnv = "TEE_VERIFIER_ADDRESS";
    string teeVerifierAddress;

    // TEE contract global variables for the tests.
    EspressoTEEVerifier espressoTEEVerifier;
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 pcr0Hash =
        bytes32(
            0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b
        );
    // Owner of the ProxyAdmin contracts that get auto-created by TransparentUpgradeableProxy.
    // Must differ from the contract owner so it can forward calls to the implementation during tests.
    address proxyAdminOwner = address(1000);

    MultiSigTransfer multiSigTransfer;

    function setUp() public {
        vm.stopPrank();
        // fork an eth sepolia network to populate the quote verifier contract code.
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/b4eb7cd43eb25061e06a5d07ecd191433c3a28988f14dd9bfb6be6a122355023"
        );

        espressoTEEVerifier = _deployTEEVerifierWithPlaceholders();
        espressoNitroTEEVerifier = _deployNitro(address(espressoTEEVerifier));
        vm.startPrank(originalOwner);
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            IEspressoNitroTEEVerifier(address(espressoNitroTEEVerifier))
        );
        vm.stopPrank();

        teeVerifierAddress = Strings.toHexString(address(espressoTEEVerifier));

        vm.setEnv(newOwnerEnv, newOwnerString);
        vm.setEnv(teeVerifierEnv, teeVerifierAddress);

        multiSigTransfer = new MultiSigTransfer();
    }

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
                (originalOwner, IEspressoNitroTEEVerifier(address(0xBEEF)))
            )
        );
        return EspressoTEEVerifier(address(proxy));
    }

    // testValidTransfer tests accepting transfers to a valid address by attempting to accept ownership with the new owner address
    // populated via `vm.setEnv`
    function testValidTransfer() public {
        // set environment variables for the transfer script.
        vm.startPrank(originalOwner);
        console2.log("original owner:", originalOwner);
        console2.log(
            "original owner according to contract:",
            Ownable(address(espressoTEEVerifier)).owner()
        );

        multiSigTransfer.transferTestEntrypoint();
        vm.stopPrank();

        // Expect emitted event from script, and initiate transfers.
        vm.startPrank(newOwner);
        console2.log("new owner:", newOwner);
        console2.log(
            "pending owner:",
            Ownable2Step(address(espressoTEEVerifier)).pendingOwner()
        );
        espressoTEEVerifier.acceptOwnership();
        assertEq(Ownable(address(espressoTEEVerifier)).owner(), newOwner);

        vm.stopPrank();
    }

    // testInvalidTransfer tests accepting transfers to a non valid address by attempting to accept ownership with the bad new owner address
    // populated via `vm.setEnv`
    function testInvalidTransfer() public {
        vm.startPrank(originalOwner);
        console2.log("original owner:", originalOwner);
        console2.log(
            "original owner according to contract:",
            Ownable(address(espressoTEEVerifier)).owner()
        );
        multiSigTransfer.transferTestEntrypoint();

        vm.stopPrank();
        // Expect emitted event from script, and initiate transfers.
        vm.startPrank(badNewOwner);
        console2.log("bad new owner:", badNewOwner);
        console2.log(
            "pending owner:",
            Ownable2Step(address(espressoTEEVerifier)).pendingOwner()
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                badNewOwner
            )
        );
        espressoTEEVerifier.acceptOwnership();

        vm.stopPrank();
    }
}
