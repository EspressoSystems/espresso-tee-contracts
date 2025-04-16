pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import {EspressoTEEVerifier} from "src/EspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";

contract DeployTEEVerifier is Script {
    // Salts for deterministic deployment
    bytes32 constant ESPRESSO_TEE_SALT = keccak256("espresso.teeverifier.v1");
    
    // Replace with your actual Nitro enclave PCR0 hash
    bytes32 constant ENCLAVE_HASH = bytes32(0xc980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293); 

    function run() external {
        vm.startBroadcast();

        address sgxVerifierAddr = vm.envAddress("SGX_VERIFIER_ADDRESS");
        address nitroVerifierAddr = vm.envAddress("NITRO_VERIFIER_ADDRESS");

        IEspressoSGXTEEVerifier sgxVerifier = IEspressoSGXTEEVerifier(sgxVerifierAddr);
        IEspressoNitroTEEVerifier nitroVerifier = IEspressoNitroTEEVerifier(nitroVerifierAddr);
        EspressoTEEVerifier verifier = new EspressoTEEVerifier(
            sgxVerifier,
            nitroVerifier
        );
        console2.log("TEEVerifier deployed at:", address(verifier));

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write Espresso address
        vm.writeJson(
            vm.serializeAddress("", "EspressoTEEVerifier", address(verifier)),
            string.concat(dir, "/", chainId, "tee-verifier.json")
        );

        vm.stopBroadcast();
    }
}