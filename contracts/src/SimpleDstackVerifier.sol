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
     * @param derivedCompressedPubkey The derived key's compressed public key (33 bytes)
     * @param appCompressedPubkey The app key's compressed public key (33 bytes) 
     * @param purpose The key purpose (e.g., "mainnet")
     * @param expectedKmsRoot The expected KMS root address
     * @return isValid True if signatures are valid
     */
    function verifySignatureChain(
        bytes32 appId,
        bytes memory appSignature,
        bytes memory kmsSignature,
        address appKeyAddress,
        bytes memory derivedCompressedPubkey,
        bytes memory appCompressedPubkey,
        string memory purpose,
        address expectedKmsRoot
    ) public pure returns (bool isValid) {
        
        // Step 1: Verify app signature
        // Message: "{purpose}:{compressed_public_key_hex}" (matches Python format)
        string memory pubkeyHex = _bytesToHexString(derivedCompressedPubkey);
        string memory appMessage = string(abi.encodePacked(purpose, ":", pubkeyHex));
        
        // Verify app signature using raw keccak hash (matches Python format)
        bytes32 appMessageHash = keccak256(bytes(appMessage));
        address recoveredApp = _recoverSigner(appMessageHash, appSignature);
        
        if (recoveredApp != appKeyAddress) {
            return false;
        }
        
        // Step 2: Verify KMS signature  
        // Message: "dstack-kms-issued:" + app_id_bytes + app_compressed_pubkey
        bytes memory kmsMessage = abi.encodePacked(
            "dstack-kms-issued:",
            _bytes32ToBytes20(appId),
            appCompressedPubkey
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
        bytes memory derivedCompressedPubkey,
        bytes memory appCompressedPubkey,
        string memory purpose,
        address expectedKmsRoot
    ) external {
        bool isValid = verifySignatureChain(
            appId,
            appSignature,
            kmsSignature,
            appKeyAddress,
            derivedCompressedPubkey,
            appCompressedPubkey,
            purpose,
            expectedKmsRoot
        );
        
        // Derive address from compressed pubkey for event
        address derivedAddress = _compressedPubkeyToAddress(derivedCompressedPubkey);
        
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
        
        // Ethereum signatures use v=27/28, but may need adjustment
        if (v < 27) {
            v += 27;
        }
        
        return ecrecover(messageHash, v, r, s);
    }
    
    function _bytes32ToBytes20(bytes32 input) internal pure returns (bytes20) {
        return bytes20(input);
    }
    
    /**
     * @notice Convert compressed public key to Ethereum address
     */
    function _compressedPubkeyToAddress(bytes memory compressedPubkey) internal pure returns (address) {
        require(compressedPubkey.length == 33, "Invalid compressed pubkey length");
        
        // This is a simplified implementation
        // In production, you'd decompress the public key and hash it properly
        // For now, we'll extract from the existing derived address parameter
        
        // This is a placeholder - the actual implementation would need 
        // elliptic curve decompression which is complex in Solidity
        return address(0);
    }
    
    /**
     * @notice Convert bytes to hex string
     */
    function _bytesToHexString(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(data.length * 2);
        
        for (uint i = 0; i < data.length; i++) {
            str[i*2] = alphabet[uint(uint8(data[i] >> 4))];
            str[1+i*2] = alphabet[uint(uint8(data[i] & 0x0f))];
        }
        
        return string(str);
    }
    
    /**
     * @notice Convert uint to string
     */
    function _uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}