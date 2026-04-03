// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifier} from "@espresso-tee/EspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "@espresso-tee/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "@espresso-tee/interface/IEspressoNitroTEEVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title DeployTEEVerifier
 * @notice Deploys EspressoTEEVerifier behind a TransparentUpgradeableProxy.
 *
 * @dev deploy() does not set guardians. run() optionally sets them via the GUARDIANS env var.
 *      To add a guardian after deployment:
 *      cast send <TEE_VERIFIER_PROXY> "addGuardian(address)" <GUARDIAN_ADDR> \
 *        --private-key $PRIVATE_KEY --rpc-url $RPC_URL
 */
contract DeployTEEVerifier is Script {
    /**
     * @param proxyAdminOwner Address that will own the auto-deployed ProxyAdmin.
     * @param sgxVerifier     Address of the EspressoSGXTEEVerifier (or address(0) as placeholder).
     * @param nitroVerifier   Address of the EspressoNitroTEEVerifier (or address(0) as placeholder).
     * @return proxy Address of the deployed TransparentUpgradeableProxy.
     * @return impl  Address of the deployed EspressoTEEVerifier implementation.
     */
    function deploy(address proxyAdminOwner, address sgxVerifier, address nitroVerifier)
        public
        returns (address proxy, address impl)
    {
        require(proxyAdminOwner != address(0), "proxyAdminOwner cannot be zero");
        EspressoTEEVerifier teeVerifierImpl = new EspressoTEEVerifier();
        console2.log("TEEVerifier implementation deployed at:", address(teeVerifierImpl));

        bytes memory initData = abi.encodeWithSelector(
            EspressoTEEVerifier.initialize.selector,
            proxyAdminOwner,
            IEspressoSGXTEEVerifier(sgxVerifier),
            IEspressoNitroTEEVerifier(nitroVerifier)
        );

        TransparentUpgradeableProxy teeProxy = new TransparentUpgradeableProxy(
            address(teeVerifierImpl), proxyAdminOwner, initData
        );
        console2.log("TEEVerifier proxy deployed at:", address(teeProxy));

        return (address(teeProxy), address(teeVerifierImpl));
    }

    function run() external {
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

        address proxyAdminOwner = vm.envOr("PROXY_ADMIN_OWNER", msg.sender);

        // Optional guardian addresses (comma-separated)
        address[] memory emptyGuardians = new address[](0);
        address[] memory guardians = vm.envOr("GUARDIANS", ",", emptyGuardians);

        vm.startBroadcast();

        (address proxy, address impl) = deploy(proxyAdminOwner, sgxVerifierAddr, nitroVerifierAddr);

        EspressoTEEVerifier teeVerifier = EspressoTEEVerifier(proxy);
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] != address(0)) {
                teeVerifier.addGuardian(guardians[i]);
                console2.log("Added guardian:", guardians[i]);
            }
        }

        vm.stopBroadcast();

        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        string memory json = "espresso_tee";
        vm.serializeAddress(json, "implementation", impl);
        string memory finalJson = vm.serializeAddress(json, "proxy", proxy);

        vm.writeJson(finalJson, string.concat(dir, "/", chainId, "-espresso-tee-verifier.json"));
    }
}
