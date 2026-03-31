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
    /**
     * @param teeVerifier          Address of the EspressoTEEVerifier proxy (controls admin functions).
     * @param nitroEnclaveVerifier Address of the AWS Nitro enclave verifier.
     */
    function deploy(address teeVerifier, address nitroEnclaveVerifier) public returns (address) {
        EspressoNitroTEEVerifier nitroVerifier =
            new EspressoNitroTEEVerifier(teeVerifier, nitroEnclaveVerifier);
        console2.log("NitroVerifier deployed at:", address(nitroVerifier));
        return address(nitroVerifier);
    }

    function run() external {
        address nitroEnclaveVerifier = vm.envAddress("NITRO_ENCLAVE_VERIFIER");
        require(
            nitroEnclaveVerifier != address(0),
            "NITRO_ENCLAVE_VERIFIER environment variable not set or invalid"
        );

        address teeVerifierAddress = vm.envAddress("TEE_VERIFIER_ADDRESS");
        require(
            teeVerifierAddress != address(0),
            "TEE_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        vm.startBroadcast();
        address nitroVerifier = deploy(teeVerifierAddress, nitroEnclaveVerifier);
        vm.stopBroadcast();

        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        string memory finalJson = vm.serializeAddress("nitro", "nitroVerifier", nitroVerifier);
        vm.writeJson(finalJson, string.concat(dir, "/", chainId, "-nitro-verifier.json"));
    }
}
