#!/usr/bin/env python3
"""
End-to-end DStack signature verification test

This script demonstrates complete signature chain verification:
1. Get KMS root address from the KMS contract
2. Extract signature data from CVM logs  
3. Verify the signature chain on-chain using the deployed verifier contract

The test validates that DStack signatures can be verified on-chain.
"""

import requests
import json
from web3 import Web3

# UPDATE THESE VALUES WITH YOUR DEPLOYMENT
CONFIG = {
    "app_id": "25e9a28b7c0cdad98c25c0ea226b1a94809e55c7",  # Your CVM app ID
    "contract_address": "0x168a832628Ed6d3425A12C215eAE44360EAf0C83",  # Your deployed verifier contract
    "cvm_url": "https://3e811bac66521aa2b1c97d385b2e8c73664cc545-8090.dstack-base-prod7.phala.network:443",  # Your CVM URL
    "rpc_url": "https://mainnet.base.org",
    "kms_contract_address": "0x2f83172A49584C017F2B256F0FB2Dca14126Ba9C"  # Base prod7 KMS contract
}

def get_kms_root_from_contract():
    """Get KMS root address from the KMS contract"""
    print("🔑 Getting KMS Root from Contract")
    print("=" * 50)
    
    try:
        # Connect to Base
        w3 = Web3(Web3.HTTPProvider(CONFIG["rpc_url"]))
        print(f"🔗 Base connection: {w3.is_connected()}")
        
        # KMS contract ABI for kmsInfo() function
        kms_abi = [{
            "inputs": [],
            "name": "kmsInfo",
            "outputs": [
                {"name": "k256Pubkey", "type": "bytes"},
                {"name": "rsaPubkey", "type": "bytes"}
            ],
            "type": "function"
        }]
        
        # Load KMS contract
        kms_contract = w3.eth.contract(
            address=CONFIG["kms_contract_address"], 
            abi=kms_abi
        )
        
        # Call kmsInfo() to get the public key
        k256_pubkey, rsa_pubkey = kms_contract.functions.kmsInfo().call()
        
        print(f"📋 KMS Contract: {CONFIG['kms_contract_address']}")
        print(f"📋 K256 Public Key: 0x{k256_pubkey.hex()}")
        
        # Derive Ethereum address from compressed public key
        from eth_utils import keccak
        from eth_keys import keys
        
        # Parse compressed public key and derive address
        compressed_pubkey = keys.PublicKey.from_compressed_bytes(k256_pubkey)
        uncompressed_bytes = compressed_pubkey.to_bytes()  # 64 bytes without 0x04 prefix
        address_hash = keccak(uncompressed_bytes)
        kms_root_address = "0x" + address_hash[-20:].hex()
        
        # Convert to checksum address for web3.py
        kms_root_checksum = w3.to_checksum_address(kms_root_address)
        
        print(f"✅ Derived KMS Root Address: {kms_root_checksum}")
        return kms_root_checksum
        
    except Exception as e:
        print(f"❌ Error getting KMS info: {e}")
        raise e

def test_dstack_signatures():
    """Get real signatures from deployed CVM"""
    print("\n🔐 Testing DStack Signature Generation")
    print("=" * 50)
    
    # Get signature data from CVM logs
    logs_url = f"{CONFIG['cvm_url']}/logs/dstack-app-1?text&bare&timestamps"
    response = requests.get(logs_url, timeout=30)
    
    if response.status_code != 200:
        raise Exception(f"CVM logs request failed: HTTP {response.status_code}")
    
    # Parse the signature data from CVM logs
    logs_text = response.text
    print(f"✅ CVM Logs received")
    
    # Look for JSON signature data in logs
    import re
    import json
    
    # Remove timestamps and extract just the JSON content
    lines = logs_text.strip().split('\n')
    json_lines = []
    in_json = False
    
    for line in lines:
        # Remove timestamp prefix
        if ' ' in line:
            content = line.split(' ', 1)[1] if len(line.split(' ', 1)) > 1 else line
        else:
            content = line
            
        if content.strip() == '{':
            in_json = True
            json_lines.append(content)
        elif in_json:
            json_lines.append(content)
            if content.strip() == '}':
                break
    
    if not json_lines:
        raise Exception("No signature data found in CVM logs")
    
    json_str = '\n'.join(json_lines)
    signature_data = json.loads(json_str)
    print(f"🔑 Found signature data with {len(signature_data)} fields")
    return signature_data

def test_contract_verification(signature_data, kms_root):
    """Test on-chain contract verification"""
    print("\n📜 Testing Contract Verification")
    print("=" * 50)
    
    try:
        # Connect to Base
        w3 = Web3(Web3.HTTPProvider(CONFIG["rpc_url"]))
        print(f"🔗 Base connection: {w3.is_connected()}")
        print(f"📊 Block: {w3.eth.block_number}")
        
        # Contract ABI
        abi = [{
            "inputs": [
                {"name": "appId", "type": "bytes32"},
                {"name": "appSignature", "type": "bytes"},
                {"name": "kmsSignature", "type": "bytes"},
                {"name": "appKeyAddress", "type": "address"},
                {"name": "derivedCompressedPubkey", "type": "bytes"},
                {"name": "appCompressedPubkey", "type": "bytes"},
                {"name": "purpose", "type": "string"},
                {"name": "expectedKmsRoot", "type": "address"}
            ],
            "name": "verifySignatureChain",
            "outputs": [{"name": "isValid", "type": "bool"}],
            "type": "function"
        }]
        
        # Load contract
        contract = w3.eth.contract(
            address=CONFIG["contract_address"], 
            abi=abi
        )
        print(f"✅ Contract loaded: {contract.address}")
        
        if signature_data:
            print(f"\n🔍 Verifying signature chain:")
            print(f"   App ID: {CONFIG['app_id']}")
            print(f"   KMS Root: {kms_root}")
            
            # Get compressed public keys
            from eth_keys import keys
            from eth_utils import keccak
            
            # Derived compressed public key
            derived_private_key = bytes.fromhex(signature_data['derived_key'])
            derived_public_key = keys.PrivateKey(derived_private_key).public_key
            derived_compressed_pubkey = derived_public_key.to_compressed_bytes()
            
            # App compressed public key (recovered from signature)
            app_message = f"mainnet:{derived_compressed_pubkey.hex()}"
            app_message_hash = keccak(text=app_message)
            app_signature_obj = keys.Signature(bytes.fromhex(signature_data["app_signature"]))
            app_compressed_pubkey = app_signature_obj.recover_public_key_from_msg_hash(app_message_hash).to_compressed_bytes()
            
            # Call the contract
            app_id_bytes32 = bytes.fromhex(CONFIG["app_id"]).ljust(32, b'\x00')
            app_sig_bytes = bytes.fromhex(signature_data["app_signature"])
            kms_sig_bytes = bytes.fromhex(signature_data["kms_signature"])
            
            result = contract.functions.verifySignatureChain(
                app_id_bytes32,
                app_sig_bytes,
                kms_sig_bytes,
                signature_data["app_address"],
                derived_compressed_pubkey,
                app_compressed_pubkey,
                "mainnet",
                kms_root
            ).call()
            
            print(f"📋 Contract verification result: {'✅ PASS' if result else '❌ FAIL'}")
            return result
        
        return False
        
    except Exception as e:
        print(f"❌ Contract verification error: {e}")
        return False

def main():
    """Run complete end-to-end test"""
    print("🚀 DStack Production End-to-End Test")
    print("=" * 60)
    print(f"App ID: {CONFIG['app_id']}")
    print(f"Contract: {CONFIG['contract_address']}")
    print(f"KMS Contract: {CONFIG['kms_contract_address']}")
    print(f"CVM URL: {CONFIG['cvm_url']}")
    print()
    
    # Step 1: Get KMS root from contract
    kms_root = get_kms_root_from_contract()
    
    # Step 2: Get signatures from CVM
    signature_data = test_dstack_signatures()
    
    # Step 3: Test contract verification 
    contract_working = test_contract_verification(signature_data, kms_root)
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Summary:")
    print(f"   KMS Root Lookup: {'✅ PASS' if kms_root else '❌ FAIL'}")
    print(f"   Signature Data: {'✅ PASS' if signature_data else '❌ FAIL'}")
    print(f"   Contract Call:  {'✅ PASS' if contract_working else '❌ FAIL'}")
    
    if all([kms_root, signature_data, contract_working]):
        print("\n🎉 End-to-end verification complete!")
        print("   ✅ DStack signature chain verified on-chain")
    else:
        print("\n❌ Verification failed - check output above")

if __name__ == "__main__":
    main()
