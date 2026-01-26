pragma solidity ^0.8.25;
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoSGXTEEVerifier} from "src/EspressoSGXTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "src/interface/IEspressoSGXTEEVerifier.sol";
import {V3QuoteVerifier} from "automata-on-chain-pccs/V3QuoteVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ServiceType} from "src/types/Types.sol";

contract DeploySGXTEEVerifier is Script {
    function run() external {
        vm.startBroadcast();

        address quoteVerifierAddr = vm.envAddress("QUOTE_VERIFIER");
        require(
            quoteVerifierAddr != address(0),
            "QUOTE_VERIFIER environment variable not set or invalid"
        );

        address finalOwner = vm.envOr("INITIAL_OWNER", msg.sender);
        require(
            finalOwner != address(0),
            "INITIAL_OWNER cannot be zero address"
        );

        // 1. Deploy implementation
        EspressoSGXTEEVerifier implementation = new EspressoSGXTEEVerifier();
        console2.log(
            "EspressoSGXTEEVerifier implementation deployed at:",
            address(implementation)
        );

        // 2. Prepare initialization data (deployer as initial owner)
        bytes memory initData = abi.encodeWithSelector(
            EspressoSGXTEEVerifier.initialize.selector,
            quoteVerifierAddr,
            msg.sender
        );

        // 3. Deploy proxy and initialize
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        EspressoSGXTEEVerifier sgxVerifier = EspressoSGXTEEVerifier(
            address(proxy)
        );
        console2.log(
            "EspressoSGXTEEVerifier proxy deployed at:",
            address(proxy)
        );

        // 4. Set initial enclave hash if provided
        bytes32 enclaveHash = vm.envOr("SGX_ENCLAVE_HASH", bytes32(0));
        if (enclaveHash != bytes32(0)) {
            console2.log("Setting initial enclave hash for BatchPoster");
            sgxVerifier.setEnclaveHash(
                enclaveHash,
                true,
                ServiceType.BatchPoster
            );
            console2.log("Setting initial enclave hash for CaffNode");
            sgxVerifier.setEnclaveHash(enclaveHash, true, ServiceType.CaffNode);
        }

        // 5. Transfer ownership if final owner is different from deployer
        if (finalOwner != msg.sender) {
            console2.log("Transferring ownership to:", finalOwner);
            sgxVerifier.transferOwnership(finalOwner);
            console2.log(
                "Ownership transferred. New owner must call acceptOwnership()"
            );
        }

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write SGX Verifier address
        string memory json = "";
        json = vm.serializeAddress(
            "",
            "Implementation",
            address(implementation)
        );
        json = vm.serializeAddress("", "Proxy", address(proxy));
        json = vm.serializeAddress(
            "",
            "EspressoSGXTEEVerifier",
            address(sgxVerifier)
        );
        json = vm.serializeAddress("", "Owner", finalOwner);
        vm.writeJson(
            json,
            string.concat(dir, "/", chainId, "-sgx-verifier.json")
        );

        vm.stopBroadcast();
    }
}
