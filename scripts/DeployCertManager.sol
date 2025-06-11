pragma solidity ^0.8.25;
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";

contract DeployCertManager is Script {
    function run() external {
        vm.startBroadcast();
        CertManager certManager = new CertManager();
        console2.log("CertManager deployed at:", address(certManager));

        // Vm string CertManager address
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");
        vm.writeJson(
            vm.serializeAddress("", "CertManager", address(certManager)),
            string.concat(dir, "/", chainId, "-cert-manager.json")
        );
        vm.stopBroadcast();
    }
}
