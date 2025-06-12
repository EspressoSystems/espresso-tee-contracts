pragma solidity ^0.8.25;
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoSGXTEEVerifier} from "src/EspressoSGXTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "src/interface/IEspressoSGXTEEVerifier.sol";

contract DeploySGXTEEVerifier is Script {
    function run() external {
        vm.startBroadcast();
        bytes32 enclaveHash = vm.envBytes32("SGX_ENCLAVE_HASH");
        address quoteVerifierAddr = vm.envAddress("SGX_QUOTE_VERIFIER_ADDRESS");
        require(enclaveHash != bytes32(0), "SGX_ENCLAVE_HASH environment variable not set or invalid");
        require(quoteVerifierAddr != address(0), "SGX_QUOTE_VERIFIER_ADDRESS environment variable not set or invalid");

        // Deploy SGX Verifier
        IEspressoSGXTEEVerifier sgxVerifier = new EspressoSGXTEEVerifier(
            enclaveHash,
            quoteVerifierAddr
        );
        console2.log("SGXVerifier deployed at:", address(sgxVerifier));

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write SGX address
        vm.writeJson(
            vm.serializeAddress("", "EspressoSGXTEEVerifier", address(sgxVerifier)),
            string.concat(dir, "/", chainId, "-sgx-verifier.json")
        );

        vm.stopBroadcast();
    }
}