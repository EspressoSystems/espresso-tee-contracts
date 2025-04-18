pragma solidity ^0.8.25;
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import {EspressoNitroTEEVerifier} from "src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "src/interface/IEspressoNitroTEEVerifier.sol";

contract DeployNitroTEEVerifier is Script {

    function run() external {
        vm.startBroadcast();

        string memory salt = vm.envString("CERT_MANAGER_SALT");
        require(bytes(salt).length > 0, "CERT_MANAGER_SALT environment variable not set");
        bytes32 CERT_MANAGER_SALT = keccak256(abi.encodePacked(salt));
        bytes32 pcr0Hash = vm.envBytes32("NITRO_ENCLAVE_HASH");
        require(pcr0Hash != bytes32(0), "NITRO_ENCLAVE_HASH environment variable not set or invalid");


        // 1. Deploy CertManager
        CertManager certManager = new CertManager{salt: CERT_MANAGER_SALT}();
        console2.log("CertManager deployed at:", address(certManager));

        // 2. Deploy NitroVerifier
        IEspressoNitroTEEVerifier nitroVerifier = new EspressoNitroTEEVerifier(
            pcr0Hash,
            certManager
        );
        console2.log("NitroVerifier deployed at:", address(nitroVerifier));

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");
        
        // Write CertManager address
        vm.writeJson(
            vm.serializeAddress("", "CertManager", address(certManager)),
            string.concat(dir, "/", chainId, "-certmanager.json")
        );

        // Write NitroVerifier address
        vm.writeJson(
            vm.serializeAddress("", "EspressoNitroTEEVerifier", address(nitroVerifier)),
            string.concat(dir, "/", chainId, "-nitro-verifier.json")
        );

        vm.stopBroadcast();
    }
}