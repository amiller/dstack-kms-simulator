#!/usr/bin/env python3
"""
End-to-end test: CVM signatures → Contract verification

This script demonstrates the complete flow:
1. Connect to your deployed Phala CVM 
2. Get real signatures from DStack KMS
3. Verify them on-chain using the deployed contract
"""

import requests
import json
from web3 import Web3
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from signature_proof import SignatureProofGenerator

# UPDATE THESE VALUES WITH YOUR DEPLOYMENT
CONFIG = {
    "app_id": "f19ecaf950c630df13440bf37a5817c6aa719658",  # Your CVM app ID
    "contract_address": "0xef67cDCdb2239349B169dce983EB2e90Db03C83F",  # Your deployed contract
    "cvm_url": "https://95fe66aa30825e071a753b08ee7b6d1c368179cf-8090.dstack-base-prod7.phala.network:443",  # Your CVM URL
    "rpc_url": "https://base.llamarpc.com",
    "kms_root": "0x2f83172A49584C017F2B256F0FB2Dca14126Ba9C"  # Base prod7 KMS
}

def test_cvm_connection():
    """Test connection to deployed CVM"""
    print("🔗 Testing CVM Connection")
    print("=" * 50)
    
    try:
        # Try to connect to CVM info endpoint
        response = requests.get(f"{CONFIG['cvm_url']}/info", timeout=10)
        if response.status_code == 200:
            info = response.json()
            print(f"✅ CVM connected: {CONFIG['cvm_url']}")
            print(f"📋 App ID: {info.get('app_id', 'N/A')}")
            return True
        else:
            print(f"❌ CVM connection failed: HTTP {response.status_code}")
            
    except Exception as e:
        print(f"❌ CVM connection error: {e}")
        print("💡 Make sure:")
        print("   1. CVM is running (check phala cvms list)")
        print("   2. Update CONFIG['cvm_url'] with your CVM's Node Info URL")
        
    return False

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

def test_contract_verification(signature_data):
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
                {"name": "derivedAddress", "type": "address"},
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
            print("\n🔍 Contract call with signature data:")
            print(f"   App ID: {CONFIG['app_id']}")
            print(f"   KMS Root: {CONFIG['kms_root']}")
            print(f"   App Address: {signature_data['app_address']}")
            print(f"   Derived Address: {signature_data['derived_address']}")
            
            # Debug: Show raw signature data for investigation
            print(f"\n🔍 Debug - Raw signature data:")
            print(f"   Derived Key: {signature_data['derived_key']}")
            print(f"   App Signature: {signature_data['app_signature']}")
            print(f"   KMS Signature: {signature_data['kms_signature']}")
            
            # Call the contract with real signature data
            app_id_bytes32 = bytes.fromhex(CONFIG["app_id"]).ljust(32, b'\x00')  # Pad to 32 bytes
            app_sig_bytes = bytes.fromhex(signature_data["app_signature"])
            kms_sig_bytes = bytes.fromhex(signature_data["kms_signature"])
            
            print(f"\n🔍 Debug - Contract call parameters:")
            print(f"   App ID (bytes32): {app_id_bytes32.hex()}")
            print(f"   App Signature length: {len(app_sig_bytes)} bytes")
            print(f"   KMS Signature length: {len(kms_sig_bytes)} bytes")
            print(f"   Purpose: mainnet")
            
            result = contract.functions.verifySignatureChain(
                app_id_bytes32,
                app_sig_bytes,
                kms_sig_bytes,
                signature_data["app_address"],
                signature_data["derived_address"],
                "mainnet",
                CONFIG["kms_root"]
            ).call()
            
            print(f"\n📋 Contract verification result: {result}")
            
            if not result:
                print(f"\n❌ Signature verification FAILED - debug data above")
            
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
    print(f"CVM URL: {CONFIG['cvm_url']}")
    print()
    
    # Step 1: Test CVM connection
    cvm_connected = test_cvm_connection()
    
    # Step 2: Get signatures from CVM
    signature_data = test_dstack_signatures()
    
    # Step 3: Test contract verification 
    contract_working = test_contract_verification(signature_data)
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Summary:")
    print(f"   CVM Connection: {'✅ PASS' if cvm_connected else '❌ FAIL'}")
    print(f"   Signature Data: {'✅ PASS' if signature_data else '❌ FAIL'}")
    print(f"   Contract Call:  {'✅ PASS' if contract_working else '❌ FAIL'}")
    
    if all([cvm_connected, signature_data, contract_working]):
        print("\n🎉 End-to-end pipeline ready!")
        print("   Next: Replace placeholders with real signature data")
    else:
        print("\n⚠️  Some components need attention - check output above")

if __name__ == "__main__":
    main()