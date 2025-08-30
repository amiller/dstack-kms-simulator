// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

/**
 * @title SimpleDstackVerifier  
 * @notice Simple DStack signature verification contract
 * @dev Demonstrates signature chain verification without external dependencies
 */
contract SimpleDstackVerifier {
    
    // Events
    event SignatureVerified(
        address indexed user,
        bytes32 indexed appId,
        address appKey,
        address derivedAddress,
        string purpose
    );
    
    event SignatureVerificationFailed(
        address indexed user,
        bytes32 indexed appId,
        string reason
    );

    /**
     * @notice Verify DStack signature chain 
     * @param appId The application ID (20 bytes, padded to 32)
     * @param appSignature Signature from app key signing derived key  
     * @param kmsSignature Signature from KMS root signing app key
     * @param appKeyAddress The app key address
     * @param derivedAddress The derived Ethereum address
     * @param purpose The key purpose (e.g., "mainnet")
     * @param expectedKmsRoot The expected KMS root address
     * @return isValid True if signatures are valid
     */
    function verifySignatureChain(
        bytes32 appId,
        bytes memory appSignature,
        bytes memory kmsSignature,
        address appKeyAddress,
        address derivedAddress,
        string memory purpose,
        address expectedKmsRoot
    ) public pure returns (bool isValid) {
        
        // Step 1: Verify app signature
        // Message: "{purpose}:{derived_address_without_0x}"
        string memory derivedAddressStr = _addressToString(derivedAddress);
        string memory appMessage = string(abi.encodePacked(purpose, ":", derivedAddressStr));
        bytes32 appMessageHash = keccak256(bytes(appMessage));
        
        address recoveredApp = _recoverSigner(appMessageHash, appSignature);
        if (recoveredApp != appKeyAddress) {
            return false;
        }
        
        // Step 2: Verify KMS signature  
        // Message: "dstack-kms-issued:" + app_id_bytes + app_address (simplified)
        bytes memory kmsMessage = abi.encodePacked(
            "dstack-kms-issued:",
            _bytes32ToBytes20(appId),
            appKeyAddress
        );
        bytes32 kmsMessageHash = keccak256(kmsMessage);
        
        address recoveredKms = _recoverSigner(kmsMessageHash, kmsSignature);
        return recoveredKms == expectedKmsRoot;
    }
    
    /**
     * @notice Authenticate and emit event if verification passes
     */
    function authenticateUser(
        bytes32 appId,
        bytes memory appSignature,
        bytes memory kmsSignature,
        address appKeyAddress,
        address derivedAddress,
        string memory purpose,
        address expectedKmsRoot
    ) external {
        bool isValid = verifySignatureChain(
            appId,
            appSignature,
            kmsSignature,
            appKeyAddress,
            derivedAddress,
            purpose,
            expectedKmsRoot
        );
        
        if (isValid) {
            emit SignatureVerified(
                msg.sender,
                appId,
                appKeyAddress,
                derivedAddress,
                purpose
            );
        } else {
            emit SignatureVerificationFailed(
                msg.sender,
                appId,
                "Invalid signature chain"
            );
        }
    }
    
    /**
     * @notice Basic signature verification utility
     */
    function verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address expectedSigner
    ) public pure returns (bool) {
        address recovered = _recoverSigner(messageHash, signature);
        return recovered == expectedSigner;
    }
    
    // Helper functions
    
    function _addressToString(address addr) internal pure returns (string memory) {
        bytes memory data = abi.encodePacked(addr);
        bytes memory alphabet = "0123456789abcdef";
        
        bytes memory str = new bytes(40);
        for (uint i = 0; i < 20; i++) {
            str[i*2] = alphabet[uint(uint8(data[i] >> 4))];
            str[1+i*2] = alphabet[uint(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }
    
    function _recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        return ecrecover(messageHash, v, r, s);
    }
    
    function _bytes32ToBytes20(bytes32 input) internal pure returns (bytes20) {
        return bytes20(input);
    }
}