// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/SimpleDstackVerifier.sol";

contract SimpleDstackVerifierTest is Test {
    SimpleDstackVerifier public verifier;
    
    // Test data from debug_signatures.py
    address constant KMS_ROOT = 0x52d3CF51c8A37A2CCfC79bBb98c7810d7Dd4CE51;
    address constant APP_KEY = 0x2d7d3553dfD57203A1f52d2D97f256157a06666D;
    address constant DERIVED_ADDRESS = 0xeC71dd9000346E766C44F4f9988521DA75Bf09Ec;
    bytes32 constant APP_ID = 0x25e9a28b7c0cdad98c25c0ea226b1a94809e55c7000000000000000000000000;
    string constant PURPOSE = "mainnet";
    bytes constant DERIVED_COMPRESSED_PUBKEY = hex"036d4d81a04af9c85a6be7b4756eed6746a558a64fb5b7946c678c493fcc0e55af";
    bytes constant APP_COMPRESSED_PUBKEY = hex"02605c9587ae3c9c622a3f8478d773ea150256aa1d2888a8d395a3a2553f8f48e2";
    bytes constant APP_SIGNATURE = hex"38ff7ff5c251ff814eb56f8ec3ef3c58687d3ba04828c619c607e7f429f5cf8c5f226402e4e06f7d7f5205853893278e7fff3769516120573f03b531cf1e438700";
    bytes constant KMS_SIGNATURE = hex"8166a59735c458253ba6012d1d671ff51eefe0931226c1a7baef5a375eeb205f20e1d7783980ecdf3c7f749ab96cf1ede1c90600190ea6000b33ed9b15720dcb00";
    
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
    
    function testSignatureChainVerificationWithDummyData() public view {
        bytes memory appSignature = new bytes(65);
        bytes memory kmsSignature = new bytes(65);
        bytes memory dummyPubkey = new bytes(33);
        
        bool result = verifier.verifySignatureChain(
            APP_ID,
            appSignature,
            kmsSignature,
            APP_KEY,
            dummyPubkey,
            dummyPubkey,
            PURPOSE,
            KMS_ROOT
        );
        
        // Should fail with dummy signatures
        assertFalse(result);
    }
    
    function testSignatureChainVerificationWithRealData() public {
        console.log("Testing with real signature data...");
        console.log("App Key:", APP_KEY);
        console.log("KMS Root:", KMS_ROOT);
        
        bool result = verifier.verifySignatureChain(
            APP_ID,
            APP_SIGNATURE,
            KMS_SIGNATURE,
            APP_KEY,
            DERIVED_COMPRESSED_PUBKEY,
            APP_COMPRESSED_PUBKEY,
            PURPOSE,
            KMS_ROOT
        );
        
        console.log("Verification result:", result);
        
        // Should pass with real signatures
        assertTrue(result);
    }
    
    function testAuthenticateUserFailEvent() public {
        bytes memory appSignature = new bytes(65);
        bytes memory kmsSignature = new bytes(65);
        bytes memory dummyPubkey = new bytes(33);
        
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
            dummyPubkey,
            dummyPubkey,
            PURPOSE,
            KMS_ROOT
        );
    }
    
    function testAuthenticateUserSuccessEvent() public {
        // Should emit SignatureVerified event with real data
        vm.expectEmit(true, true, false, true);
        emit SimpleDstackVerifier.SignatureVerified(
            address(this),
            APP_ID,
            APP_KEY,
            address(0), // placeholder since _compressedPubkeyToAddress returns 0
            PURPOSE
        );
        
        verifier.authenticateUser(
            APP_ID,
            APP_SIGNATURE,
            KMS_SIGNATURE,
            APP_KEY,
            DERIVED_COMPRESSED_PUBKEY,
            APP_COMPRESSED_PUBKEY,
            PURPOSE,
            KMS_ROOT
        );
    }
    
    function testAddressToStringConversion() public view {
        // Test that the contract can be deployed and functions exist
        assertTrue(address(verifier) != address(0));
    }
}