// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {
    OwnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
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
    EspressoSGXTEEVerifier espressoSGXTEEVerifier;
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 enclaveHash =
        bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0);
    //  Address of the automata V3QuoteVerifier deployed on sepolia
    address v3QuoteVerifier = address(0x6E64769A13617f528a2135692484B681Ee1a7169);
    bytes32 pcr0Hash = bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b);
    // Admin must differ from the owner so it can forward calls to the implementation during tests.
    address proxyAdmin = address(1000);

    MultiSigTransfer multiSigTransfer;

    function setUp() public {
        vm.stopPrank();
        // fork an eth sepolia network to populate the quote verifier contract code.
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );

        espressoTEEVerifier = _deployTEEVerifierWithPlaceholders();
        espressoSGXTEEVerifier = _deploySGX(address(espressoTEEVerifier));
        espressoNitroTEEVerifier = _deployNitro(address(espressoTEEVerifier));
        vm.startPrank(originalOwner);
        espressoTEEVerifier.setEspressoSGXTEEVerifier(
            IEspressoSGXTEEVerifier(address(espressoSGXTEEVerifier))
        );
        espressoTEEVerifier.setEspressoNitroTEEVerifier(
            IEspressoNitroTEEVerifier(address(espressoNitroTEEVerifier))
        );
        vm.stopPrank();

        teeVerifierAddress = Strings.toHexString(address(espressoTEEVerifier));

        vm.setEnv(newOwnerEnv, newOwnerString);
        vm.setEnv(teeVerifierEnv, teeVerifierAddress);

        multiSigTransfer = new MultiSigTransfer();
    }

    function _deploySGX(address teeVerifier) internal returns (EspressoSGXTEEVerifier) {
        EspressoSGXTEEVerifier impl = new EspressoSGXTEEVerifier();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            proxyAdmin,
            abi.encodeCall(EspressoSGXTEEVerifier.initialize, (teeVerifier, v3QuoteVerifier))
        );
        return EspressoSGXTEEVerifier(address(proxy));
    }

    function _deployNitro(address teeVerifier) internal returns (EspressoNitroTEEVerifier) {
        EspressoNitroTEEVerifier impl = new EspressoNitroTEEVerifier();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            proxyAdmin,
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
            proxyAdmin,
            abi.encodeCall(
                EspressoTEEVerifier.initialize,
                (
                    originalOwner,
                    IEspressoSGXTEEVerifier(address(0xDEAD)),
                    IEspressoNitroTEEVerifier(address(0xBEEF))
                )
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
            "original owner according to contract:", Ownable(address(espressoTEEVerifier)).owner()
        );

        multiSigTransfer.transferTestEntrypoint();
        vm.stopPrank();

        // Expect emitted event from script, and initiate transfers.
        vm.startPrank(newOwner);
        console2.log("new owner:", newOwner);
        console2.log("pending owner:", Ownable2Step(address(espressoTEEVerifier)).pendingOwner());
        espressoTEEVerifier.acceptOwnership();
        assertEq(Ownable(address(espressoTEEVerifier)).owner(), newOwner);

        vm.stopPrank();
    }

    // testInvalidTransfer tests accepting transfers to a non valid address by attempting to accept ownership with the bad new owner address
    // populated via `vm.setEnv`
    function testInvalidTransfer() public {
        // set environment variables for the transfer script.
        // vm.setEnv(newOwnerEnv, newOwnerString);
        // vm.setEnv(teeVerifierEnv, teeVerifierAddress);

        vm.startPrank(originalOwner);
        console2.log("original owner:", originalOwner);
        console2.log(
            "original owner according to contract:", Ownable(address(espressoTEEVerifier)).owner()
        );
        multiSigTransfer.transferTestEntrypoint();

        vm.stopPrank();
        // Expect emitted event from script, and initiate transfers.
        vm.startPrank(badNewOwner);
        console2.log("bad new owner:", badNewOwner);
        console2.log("pending owner:", Ownable2Step(address(espressoTEEVerifier)).pendingOwner());
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, badNewOwner
            )
        );
        espressoTEEVerifier.acceptOwnership();

        vm.stopPrank();
    }
}
