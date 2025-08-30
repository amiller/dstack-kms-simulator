#!/usr/bin/env python3
"""
Simple test script for DStack signature verification using signature_proof module.
"""

import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from signature_proof import SignatureProofGenerator
from eth_account import Account

# KMS root key from simulator appkeys.json
KMS_ROOT_PRIVATE_KEY = "e0e5d254fb944dcc370a2e5288b336a1e809871545a73ee645368957fefa31f9"
KMS_ROOT_ADDRESS = Account.from_key(KMS_ROOT_PRIVATE_KEY).address

def main():
    print("🔐 Testing DStack Signature Verification")
    print(f"Expected KMS root: {KMS_ROOT_ADDRESS}")
    
    # Use signature_proof module for verification
    generator = SignatureProofGenerator('./simulator/dstack.sock')
    
    try:
        # Generate proof
        proof = generator.generate_proof('wallet/ethereum', 'mainnet')
        print(f"✅ Generated proof for key path 'wallet/ethereum'")
        print(f"App ID: {proof.app_id}")
        
        # Get derived address for display
        derived_account = Account.from_key(proof.derived_private_key)
        print(f"Derived address: {derived_account.address}")
        
        # Verify proof using signature_proof module
        is_valid = generator.verify_proof(proof, KMS_ROOT_ADDRESS)
        
        if is_valid:
            print("✅ Signature chain verification PASSED")
            print("   Key was issued by authenticated KMS to attested TEE")
        else:
            print("❌ Signature chain verification FAILED")
            print(f"   Expected KMS: {KMS_ROOT_ADDRESS}")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    
    return is_valid

if __name__ == "__main__":
    main()