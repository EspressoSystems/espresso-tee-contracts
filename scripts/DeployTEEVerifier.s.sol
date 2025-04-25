pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import {EspressoTEEVerifier} from "src/EspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";

contract DeployTEEVerifier is Script {

    function run() external {
        vm.startBroadcast();

        address sgxVerifierAddr = vm.envAddress("SGX_VERIFIER_ADDRESS");
        address nitroVerifierAddr = vm.envAddress("NITRO_VERIFIER_ADDRESS");

        require(sgxVerifierAddr != address(0), "SGX_VERIFIER_ADDRESS environment variable not set or invalid");
        require(nitroVerifierAddr != address(0), "nitroVerifierAddr environment variable not set or invalid");

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
            string.concat(dir, "/", chainId, "-espresso-tee-verifier.json")
        );

        vm.stopBroadcast();
    }
}