#!/usr/bin/env python3
"""
Simple test script for DStack signature verification.
Tests get_key() and verifies signature chain against KMS root key.
"""

import dstack_sdk
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak
from eth_keys import keys

# KMS root key from simulator appkeys.json
KMS_ROOT_PRIVATE_KEY = "e0e5d254fb944dcc370a2e5288b336a1e809871545a73ee645368957fefa31f9"
KMS_ROOT_ADDRESS = Account.from_key(KMS_ROOT_PRIVATE_KEY).address

def main():
    print("🔐 Testing DStack Signature Verification")
    print(f"Expected KMS root: {KMS_ROOT_ADDRESS}")
    
    # Connect to DStack
    client = dstack_sdk.DstackClient('./simulator/dstack.sock')
    
    # Get instance info
    info = client.info()
    print(f"App ID: {info.app_id}")
    print(f"Instance ID: {info.instance_id}")
    
    # Get a key with signature chain
    key_response = client.get_key('wallet/ethereum', 'mainnet')
    print(f"✅ Got key with {len(key_response.signature_chain)} signatures")
    
    # Extract components
    derived_private_key = key_response.key
    signature_chain = key_response.signature_chain
    app_signature = signature_chain[0]  # App signed derived key
    kms_signature = signature_chain[1]  # KMS signed app key
    
    print(f"App signature length: {len(app_signature)} bytes")
    print(f"KMS signature length: {len(kms_signature)} bytes")
    print(f"App signature: {app_signature}")
    print(f"KMS signature: {kms_signature}")
    
    # Convert signatures to bytes
    if isinstance(app_signature, str):
        app_signature = bytes.fromhex(app_signature.replace('0x', ''))
    if isinstance(kms_signature, str):
        kms_signature = bytes.fromhex(kms_signature.replace('0x', ''))
    
    # Get derived public key address
    derived_account = Account.from_key(derived_private_key)
    derived_address = derived_account.address
    print(f"Derived address: {derived_address}")
    
    # Step 1: Verify app key signed the derived key
    # The guest agent signs: "{purpose}:{derived_pubkey_sec1_hex}" not the address!
    derived_private_bytes = bytes.fromhex(derived_private_key.replace('0x', ''))
    derived_public_key = keys.PrivateKey(derived_private_bytes).public_key
    derived_pubkey_sec1 = derived_public_key.to_compressed_bytes()
    message = f"mainnet:{derived_pubkey_sec1.hex()}"
    message_hash = keccak(text=message)
    app_account = Account._recover_hash(message_hash, signature=app_signature)
    print(f"App key recovered: {app_account}")
    print(f"Message signed by app: {message}")
    
    # Read the actual k256_key from appkeys.json
    import json
    with open('simulator/appkeys.json', 'r') as f:
        appkeys = json.load(f)
    k256_key = appkeys['k256_key']
    k256_account = Account.from_key(k256_key)
    print(f"k256_key from appkeys.json corresponds to address: {k256_account.address}")
    
    # Step 1.5: Check if app key matches expected k256 key from simulator
    if app_account.lower() == k256_account.address.lower():
        print("✅ App key matches k256 key from simulator")
    else:
        print(f"❌ App key mismatch - recovered: {app_account}, expected k256: {k256_account.address}")
    
    # Step 2: Verify KMS signed the app key
    # The message format should be: "dstack-kms-issued:" + app_id + app_public_key_sec1
    app_id_hex = info.app_id.replace('0x', '')  # Remove 0x prefix if present
    app_id_bytes = bytes.fromhex(app_id_hex)
    # Get the app key's public key (not the derived key's public key!)
    app_private_bytes = bytes.fromhex(k256_key)
    app_public_key = keys.PrivateKey(app_private_bytes).public_key
    app_pubkey_sec1 = app_public_key.to_compressed_bytes()
    kms_message = b"dstack-kms-issued:" + app_id_bytes + app_pubkey_sec1
    kms_message_hash = keccak(kms_message)
    recovered_kms = Account._recover_hash(kms_message_hash, signature=kms_signature)
    print(f"KMS key recovered: {recovered_kms}")
    print(f"App public key (SEC1): {app_pubkey_sec1.hex()}")
    print(f"KMS message: {kms_message.hex()}")
    print(f"App ID: {info.app_id} -> {app_id_hex}")
    
    # Step 3: Verify against expected KMS root  
    is_valid = recovered_kms.lower() == KMS_ROOT_ADDRESS.lower()
    
    if is_valid:
        print("✅ Signature chain verification PASSED")
        print("   Key was issued by authenticated KMS to attested TEE")
    else:
        print("❌ Signature chain verification FAILED")
        print(f"   Expected KMS: {KMS_ROOT_ADDRESS}")
        print(f"   Recovered KMS: {recovered_kms}")

if __name__ == "__main__":
    main()