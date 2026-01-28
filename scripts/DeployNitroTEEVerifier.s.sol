pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoNitroTEEVerifier} from "src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "src/interface/IEspressoNitroTEEVerifier.sol";
import {INitroEnclaveVerifier} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

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

        // PROXY_ADMIN_OWNER is the address that will own the auto-deployed ProxyAdmin
        // If not set, defaults to msg.sender
        address proxyAdminOwner = vm.envOr("PROXY_ADMIN_OWNER", msg.sender);

        // 1. Deploy NitroVerifier implementation
        EspressoNitroTEEVerifier nitroVerifierImpl = new EspressoNitroTEEVerifier();
        console2.log(
            "NitroVerifier implementation deployed at:",
            address(nitroVerifierImpl)
        );

        // 2. Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            EspressoNitroTEEVerifier.initialize.selector,
            teeVerifierAddress,
            INitroEnclaveVerifier(nitroEnclaveVerifier)
        );

        // 3. Deploy TransparentUpgradeableProxy (v5.x pattern)
        // ProxyAdmin is automatically deployed internally with proxyAdminOwner as its owner
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(nitroVerifierImpl),
            proxyAdminOwner,
            initData
        );
        console2.log("NitroVerifier proxy deployed at:", address(proxy));

        vm.stopBroadcast();

        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        string memory json = "nitro";
        vm.serializeAddress(json, "implementation", address(nitroVerifierImpl));
        string memory finalJson = vm.serializeAddress(
            json,
            "proxy",
            address(proxy)
        );

        vm.writeJson(
            finalJson,
            string.concat(dir, "/", chainId, "-nitro-verifier.json")
        );
    }
}
