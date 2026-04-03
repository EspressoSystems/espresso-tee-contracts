// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoSGXTEEVerifier} from "@espresso-tee/EspressoSGXTEEVerifier.sol";

/**
 * @title DeploySGXTEEVerifier
 * @notice Deploys EspressoSGXTEEVerifier as a non-proxy contract.
 */
contract DeploySGXTEEVerifier is Script {
    /**
     * @param teeVerifier   Address of the EspressoTEEVerifier proxy (controls admin functions).
     * @param quoteVerifier Address of the SGX quote verifier (from Automata).
     */
    function deploy(address teeVerifier, address quoteVerifier) public returns (address) {
        EspressoSGXTEEVerifier sgxVerifier = new EspressoSGXTEEVerifier(teeVerifier, quoteVerifier);
        console2.log("SGXVerifier deployed at:", address(sgxVerifier));
        return address(sgxVerifier);
    }

    function run() external {
        address quoteVerifierAddr = vm.envAddress("SGX_QUOTE_VERIFIER_ADDRESS");
        require(
            quoteVerifierAddr != address(0),
            "SGX_QUOTE_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        address teeVerifierAddress = vm.envAddress("TEE_VERIFIER_ADDRESS");
        require(
            teeVerifierAddress != address(0),
            "TEE_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        vm.startBroadcast();
        address sgxVerifier = deploy(teeVerifierAddress, quoteVerifierAddr);
        vm.stopBroadcast();

        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        string memory finalJson = vm.serializeAddress("sgx", "sgxVerifier", sgxVerifier);
        vm.writeJson(finalJson, string.concat(dir, "/", chainId, "-sgx-verifier.json"));
    }
}
