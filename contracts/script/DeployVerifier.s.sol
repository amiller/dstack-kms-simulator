// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import "../src/SimpleDstackVerifier.sol";

contract DeployVerifier is Script {
    function run() external {
        vm.startBroadcast();
        
        SimpleDstackVerifier verifier = new SimpleDstackVerifier();
        
        console.log("SimpleDstackVerifier deployed to:", address(verifier));
        
        vm.stopBroadcast();
    }
}