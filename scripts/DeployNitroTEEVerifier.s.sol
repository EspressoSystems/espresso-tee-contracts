pragma solidity ^0.8.25;
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoNitroTEEVerifier} from "src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "src/interface/IEspressoNitroTEEVerifier.sol";
import {INitroEnclaveVerifier} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ServiceType} from "src/types/Types.sol";

contract DeployNitroTEEVerifier is Script {
    function run() external {
        vm.startBroadcast();

        address nitroEnclaveVerifier = vm.envAddress("NITRO_ENCLAVE_VERIFIER");
        require(
            nitroEnclaveVerifier != address(0),
            "NITRO_ENCLAVE_VERIFIER environment variable not set or invalid"
        );

        address finalOwner = vm.envOr("INITIAL_OWNER", msg.sender);
        require(
            finalOwner != address(0),
            "INITIAL_OWNER cannot be zero address"
        );

        // 1. Deploy implementation
        EspressoNitroTEEVerifier implementation = new EspressoNitroTEEVerifier();
        console2.log(
            "EspressoNitroTEEVerifier implementation deployed at:",
            address(implementation)
        );

        // 2. Prepare initialization data (deployer as initial owner)
        bytes memory initData = abi.encodeWithSelector(
            EspressoNitroTEEVerifier.initialize.selector,
            msg.sender,
            INitroEnclaveVerifier(nitroEnclaveVerifier)
        );

        // 3. Deploy proxy and initialize
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(implementation),
            msg.sender,
            initData
        );
        EspressoNitroTEEVerifier nitroVerifier = EspressoNitroTEEVerifier(
            address(proxy)
        );
        console2.log(
            "EspressoNitroTEEVerifier proxy deployed at:",
            address(proxy)
        );

        // 4. Set initial enclave hash if provided
        bytes32 pcr0Hash = vm.envOr("NITRO_ENCLAVE_HASH", bytes32(0));
        if (pcr0Hash != bytes32(0)) {
            console2.log("Setting initial enclave hash for BatchPoster");
            nitroVerifier.setEnclaveHash(
                pcr0Hash,
                true,
                ServiceType.BatchPoster
            );
            console2.log("Setting initial enclave hash for CaffNode");
            nitroVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.CaffNode);
        }

        // 5. Transfer ownership if final owner is different from deployer
        if (finalOwner != msg.sender) {
            console2.log("Transferring ownership to:", finalOwner);
            nitroVerifier.transferOwnership(finalOwner);
            console2.log(
                "Ownership transferred. New owner must call acceptOwnership()"
            );
        }

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write NitroVerifier address
        string memory json = "";
        json = vm.serializeAddress(
            "",
            "Implementation",
            address(implementation)
        );
        json = vm.serializeAddress("", "Proxy", address(proxy));
        json = vm.serializeAddress(
            "",
            "EspressoNitroTEEVerifier",
            address(nitroVerifier)
        );
        json = vm.serializeAddress("", "Owner", finalOwner);
        vm.writeJson(
            json,
            string.concat(dir, "/", chainId, "-nitro-verifier.json")
        );

        vm.stopBroadcast();
    }
}
