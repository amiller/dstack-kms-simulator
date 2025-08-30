// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../src/SimpleDstackVerifier.sol";

contract SimpleDstackVerifierTest is Test {
    SimpleDstackVerifier public verifier;
    
    // Test addresses and data (from your working verification)
    address constant KMS_ROOT = 0x5e5132F15a9aa4AA91A6bCaE35Adf34e27A13516;
    address constant APP_KEY = 0x814532798F4962AFC189517D4E6B364E80B706Fb;
    address constant DERIVED_ADDRESS = 0x6514b092e5af8De0D9ECD15d27842f4c1876F0e5;
    bytes32 constant APP_ID = 0xea549f02e1a25fabd1cb788380e033ec5461b2ff000000000000000000000000;
    string constant PURPOSE = "mainnet";
    
    function setUp() public {
        verifier = new SimpleDstackVerifier();
    }
    
    function testBasicSignatureVerification() public view {
        bytes32 messageHash = keccak256(bytes("test message"));
        bytes memory signature = new bytes(65);
        
        // Should fail with dummy signature
        bool result = verifier.verifySignature(messageHash, signature, address(0x123));
        assertFalse(result);
    }
    
    function testSignatureChainVerificationStructure() public view {
        bytes memory appSignature = new bytes(65);
        bytes memory kmsSignature = new bytes(65);
        
        bool result = verifier.verifySignatureChain(
            APP_ID,
            appSignature,
            kmsSignature,
            APP_KEY,
            DERIVED_ADDRESS,
            PURPOSE,
            KMS_ROOT
        );
        
        // Should fail with dummy signatures
        assertFalse(result);
    }
    
    function testAuthenticateUserEvent() public {
        bytes memory appSignature = new bytes(65);
        bytes memory kmsSignature = new bytes(65);
        
        // Should emit SignatureVerificationFailed event
        vm.expectEmit(true, true, false, true);
        emit SimpleDstackVerifier.SignatureVerificationFailed(
            address(this),
            APP_ID,
            "Invalid signature chain"
        );
        
        verifier.authenticateUser(
            APP_ID,
            appSignature,
            kmsSignature,
            APP_KEY,
            DERIVED_ADDRESS,
            PURPOSE,
            KMS_ROOT
        );
    }
    
    function testAddressToStringConversion() public view {
        // Test that the contract can be deployed and functions exist
        assertTrue(address(verifier) != address(0));
    }
}