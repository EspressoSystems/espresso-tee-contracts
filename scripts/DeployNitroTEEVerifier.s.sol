pragma solidity ^0.8.25;
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import {EspressoNitroTEEVerifier} from "src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "src/interface/IEspressoNitroTEEVerifier.sol";

contract DeployNitroTEEVerifier is Script {
    function run() external {
        vm.startBroadcast();

        address certManager = vm.envAddress("CERT_MANAGER_ADDRESS");
        require(
            certManager != address(0),
            "CERT_MANAGER_ADDRESS environment variable not set or invalid"
        );
        bytes32 pcr0Hash = vm.envBytes32("NITRO_ENCLAVE_HASH");
        require(
            pcr0Hash != bytes32(0),
            "NITRO_ENCLAVE_HASH environment variable not set or invalid"
        );

        // 1. Deploy NitroVerifier
        IEspressoNitroTEEVerifier nitroVerifier = new EspressoNitroTEEVerifier(
            pcr0Hash,
            CertManager(certManager)
        );
        console2.log("NitroVerifier deployed at:", address(nitroVerifier));

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write NitroVerifier address
        vm.writeJson(
            vm.serializeAddress(
                "",
                "EspressoNitroTEEVerifier",
                address(nitroVerifier)
            ),
            string.concat(dir, "/", chainId, "-nitro-verifier.json")
        );

        vm.stopBroadcast();
    }
}
