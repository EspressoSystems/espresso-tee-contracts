// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifier} from "@espresso-tee/EspressoTEEVerifier.sol";

/**
 * @title DeployTEEVerifierImpl
 * @notice Deploys only the EspressoTEEVerifier implementation contract, with no proxy.
 * @dev Import this (instead of DeployTEEVerifier.s.sol) when you need to deploy the
 *      implementation and bring your own proxy.
 */
contract DeployTEEVerifierImpl is Script {
    function deploy() public returns (address impl) {
        impl = address(new EspressoTEEVerifier());
        console2.log("TEEVerifier implementation deployed at:", impl);
    }
}
