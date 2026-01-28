pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifier} from "src/EspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "src/interface/IEspressoNitroTEEVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract DeployTEEVerifier is Script {
    function run() external {
        vm.startBroadcast();

        address sgxVerifierAddr = vm.envAddress("SGX_VERIFIER_ADDRESS");
        address nitroVerifierAddr = vm.envAddress("NITRO_VERIFIER_ADDRESS");

        require(
            sgxVerifierAddr != address(0),
            "SGX_VERIFIER_ADDRESS environment variable not set or invalid"
        );
        require(
            nitroVerifierAddr != address(0),
            "NITRO_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        // PROXY_ADMIN_OWNER is the address that will own the auto-deployed ProxyAdmin
        // If not set, defaults to msg.sender
        address proxyAdminOwner = vm.envOr("PROXY_ADMIN_OWNER", msg.sender);

        // 1. Deploy TEEVerifier implementation
        EspressoTEEVerifier teeVerifierImpl = new EspressoTEEVerifier();
        console2.log(
            "TEEVerifier implementation deployed at:",
            address(teeVerifierImpl)
        );

        // 2. Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            EspressoTEEVerifier.initialize.selector,
            proxyAdminOwner,
            IEspressoSGXTEEVerifier(sgxVerifierAddr),
            IEspressoNitroTEEVerifier(nitroVerifierAddr)
        );

        // 3. Deploy TransparentUpgradeableProxy (v5.x pattern)
        // ProxyAdmin is automatically deployed internally with proxyAdminOwner as its owner
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(teeVerifierImpl),
            proxyAdminOwner,
            initData
        );
        console2.log("TEEVerifier proxy deployed at:", address(proxy));

        vm.stopBroadcast();

        // Save deployment artifacts (outside of broadcast to avoid gas costs)
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write deployment addresses
        string memory json = "espresso_tee";
        vm.serializeAddress(json, "implementation", address(teeVerifierImpl));
        string memory finalJson = vm.serializeAddress(
            json,
            "proxy",
            address(proxy)
        );

        vm.writeJson(
            finalJson,
            string.concat(dir, "/", chainId, "-espresso-tee-verifier.json")
        );
    }
}
