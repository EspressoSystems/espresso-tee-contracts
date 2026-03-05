pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoSGXTEEVerifier} from "@espresso-tee/EspressoSGXTEEVerifier.sol";

/**
 * @title DeploySGXTEEVerifier
 * @notice Deploys EspressoSGXTEEVerifier as a non-proxy contract.
 */
contract DeploySGXTEEVerifier is Script {
    function run() external {
        vm.startBroadcast();

        address quoteVerifierAddr = vm.envAddress("SGX_QUOTE_VERIFIER_ADDRESS");
        require(
            quoteVerifierAddr != address(0),
            "SGX_QUOTE_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        // TEE_VERIFIER_ADDRESS is the address of the main EspressoTEEVerifier proxy
        // This is used to set the teeVerifier in the SGXTEEVerifier which controls admin functions
        address teeVerifierAddress = vm.envAddress("TEE_VERIFIER_ADDRESS");
        require(
            teeVerifierAddress != address(0),
            "TEE_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        EspressoSGXTEEVerifier sgxVerifier =
            new EspressoSGXTEEVerifier(teeVerifierAddress, quoteVerifierAddr);
        console2.log("SGXVerifier deployed at:", address(sgxVerifier));

        vm.stopBroadcast();

        // Save deployment artifacts (outside of broadcast to avoid gas costs)
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        string memory finalJson =
            vm.serializeAddress("sgx", "sgxVerifier", address(sgxVerifier));

        vm.writeJson(finalJson, string.concat(dir, "/", chainId, "-sgx-verifier.json"));
    }
}
