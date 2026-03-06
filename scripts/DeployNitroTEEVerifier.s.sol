pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoNitroTEEVerifier} from "@espresso-tee/EspressoNitroTEEVerifier.sol";
import {INitroEnclaveVerifier} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title DeployNitroTEEVerifier
 * @notice Deploys EspressoNitroTEEVerifier as a non-proxy contract.
 */
contract DeployNitroTEEVerifier is Script {
    function run() external {
        vm.startBroadcast();

        address nitroEnclaveVerifier = vm.envAddress("NITRO_ENCLAVE_VERIFIER");
        require(
            nitroEnclaveVerifier != address(0),
            "NITRO_ENCLAVE_VERIFIER environment variable not set or invalid"
        );

        // TEE_VERIFIER_ADDRESS is the address of the main EspressoTEEVerifier proxy
        // This is used to set the teeVerifier in the NitroTEEVerifier which controls admin functions
        address teeVerifierAddress = vm.envAddress("TEE_VERIFIER_ADDRESS");
        require(
            teeVerifierAddress != address(0),
            "TEE_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        EspressoNitroTEEVerifier nitroVerifier = new EspressoNitroTEEVerifier(
            teeVerifierAddress, nitroEnclaveVerifier
        );
        console2.log("NitroVerifier deployed at:", address(nitroVerifier));

        vm.stopBroadcast();

        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        string memory finalJson =
            vm.serializeAddress("nitro", "nitroVerifier", address(nitroVerifier));

        vm.writeJson(finalJson, string.concat(dir, "/", chainId, "-nitro-verifier.json"));
    }
}
