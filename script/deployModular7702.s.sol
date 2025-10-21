// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {Modular7702} from "../src/Modular7702.sol";

/*

forge script script/deployModular7702.s.sol --rpc-url https://sepolia.base.org --broadcast --verify

*/

contract DeployModular7702Script is Script {
    function setUp() public {}

    function run() public {
        address deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        console.log("Deployer", deployer);

        bytes32 salt = vm.envBytes32("SALT");

        vm.startBroadcast();

        Modular7702 modular7702 = new Modular7702{salt: salt}();

        console.log("Deployed Modular7702 at", address(modular7702));

        vm.stopBroadcast();
    }
}
