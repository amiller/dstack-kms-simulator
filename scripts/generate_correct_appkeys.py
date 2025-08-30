#!/usr/bin/env python3
"""
Generate a correct appkeys.json with proper KMS-derived app key and signature
based on the actual KMS derivation process from the code
"""

import json
from eth_account import Account
from eth_utils import keccak
from ecdsa import SigningKey as EcdsaSigningKey, SECP256k1
import hashlib
import hmac

def kdf_derive_ecdsa_key(parent_key_bytes, context_data, length):
    """
    Simulate the KMS key derivation function
    This is a simplified version - the real KMS uses ra_tls::kdf
    """
    # Combine context data
    context = b"".join(context_data)
    
    # Use HMAC-based key derivation (simplified)
    # Real implementation would use HKDF or similar
    derived = hmac.new(parent_key_bytes, context, hashlib.sha256).digest()
    return derived[:length]

def sign_message_keccak(signing_key_bytes, prefix, app_id, message):
    """
    Implement the KMS sign_message function exactly as in the code
    """
    # Construct message: prefix + ":" + app_id + message  
    full_message = prefix + b":" + app_id + message
    
    # Hash with Keccak256
    message_hash = keccak(full_message)
    
    # Sign with recovery using eth_account
    account = Account.from_key(signing_key_bytes)
    signature = account._key_obj.sign_msg_hash(message_hash)
    
    # Format: r + s + v (recovery_id)
    signature_bytes = signature.r.to_bytes(32, 'big') + signature.s.to_bytes(32, 'big') + bytes([signature.v])
    
    return signature_bytes

def main():
    print("🔧 Generating Correct appkeys.json")
    
    # KMS root key (same as current simulator)
    kms_root_private_key = "e0e5d254fb944dcc370a2e5288b336a1e809871545a73ee645368957fefa31f9"
    kms_root_key_bytes = bytes.fromhex(kms_root_private_key)
    
    # App ID (same as current simulator) 
    app_id = "ea549f02e1a25fabd1cb788380e033ec5461b2ff"
    app_id_bytes = bytes.fromhex(app_id)
    
    print(f"KMS Root Private Key: {kms_root_private_key}")
    print(f"App ID: {app_id}")
    
    # Step 1: Derive app key using KMS process
    context_data = [app_id_bytes, b"app-key"]
    derived_app_key_bytes = kdf_derive_ecdsa_key(kms_root_key_bytes, context_data, 32)
    
    print(f"Derived App Key: {derived_app_key_bytes.hex()}")
    
    # Get app key public key
    app_signing_key = EcdsaSigningKey.from_string(derived_app_key_bytes, curve=SECP256k1)
    app_public_key_sec1 = app_signing_key.get_verifying_key().to_string("compressed")
    app_address = Account.from_key(derived_app_key_bytes).address
    
    print(f"App Key Address: {app_address}")
    print(f"App Public Key (SEC1): {app_public_key_sec1.hex()}")
    
    # Step 2: KMS root signs the app key
    kms_signature = sign_message_keccak(
        kms_root_key_bytes,
        b"dstack-kms-issued",
        app_id_bytes, 
        app_public_key_sec1
    )
    
    print(f"KMS Signature: {kms_signature.hex()}")
    
    # Step 3: Verify the signature works
    print(f"\n🔍 Verifying KMS signature...")
    
    message = b"dstack-kms-issued:" + app_id_bytes + app_public_key_sec1
    message_hash = keccak(message)
    
    try:
        recovered_kms = Account._recover_hash(message_hash, signature=kms_signature)
        kms_root_address = Account.from_key(kms_root_private_key).address
        
        if recovered_kms.lower() == kms_root_address.lower():
            print(f"✅ KMS signature verification PASSED!")
            print(f"   Recovered: {recovered_kms}")
            print(f"   Expected:  {kms_root_address}")
        else:
            print(f"❌ KMS signature verification FAILED!")
            print(f"   Recovered: {recovered_kms}")
            print(f"   Expected:  {kms_root_address}")
    except Exception as e:
        print(f"❌ Signature verification error: {e}")
    
    # Step 4: Generate corrected appkeys.json
    print(f"\n📝 Generating corrected appkeys.json...")
    
    # Use existing values for other fields
    corrected_appkeys = {
        "disk_crypt_key": "1122e1f340c19407adc5ec531ac98d72bcf702bf7858f6fa49b5be79b61e4d5b",
        "env_crypt_key": "ca1a3895d9d613287fc14034d0ec60abb5089896e7c8fd7c2f02bd91fa0076aa",
        "k256_key": derived_app_key_bytes.hex(),  # Use derived app key
        "k256_signature": kms_signature.hex(),   # Use correct KMS signature
        "gateway_app_id": "any",
        "ca_cert": "-----BEGIN CERTIFICATE-----\nMIIBmTCCAUCgAwIBAgIUU7801+krCs2OpIdne3t6OWrJ2fMwCgYIKoZIzj0EAwIw\nKTEPMA0GA1UECgwGRHN0YWNrMRYwFAYDVQQDDA1Ec3RhY2sgS01TIENBMB4XDTc1\nMDEwMTAwMDAwMFoXDTM1MDMxNzA5NDQ0MlowKTEPMA0GA1UECgwGRHN0YWNrMRYw\nFAYDVQQDDA1Ec3RhY2sgS01TIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\nGbJFfdm4qmRG2YDxNv/3gS7NbHd0DusOKLENVsDAACiltuWdzqMH1YO9H3B2npwR\nbfK8+xdYqV2GE+feHISCwKNGMEQwDwYDVR0PAQH/BAUDAweAADAdBgNVHQ4EFgQU\nevjJ+VZPvDxHJ2ejjeIaUYMMcEcwEgYDVR0TAQH/BAgwBgEB/wIBATAKBggqhkjO\nPQQDAgNHADBEAiAhQHQNbmyvx9BDBXRjW1eCkPCpFs/2Vt/nvbi+M69FPAIgQ13F\n3pmxicxyFeVW2iOjrbG1cxLdT9Kh+9ICF9zn8kA=\n-----END CERTIFICATE-----\n",
        "key_provider": {
            "None": {
                "key": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1PYCFKYfDmUfv5fk\nstppasf4mPGqnz0fEoLEnGx8CnKhRANCAAQZskV92biqZEbZgPE2//eBLs1sd3QO\n6w4osQ1WwMAAKKW25Z3OowfVg70fcHaenBFt8rz7F1ipXYYT594chILA\n-----END PRIVATE KEY-----\n"
            }
        }
    }
    
    # Write to file
    with open('corrected_appkeys.json', 'w') as f:
        json.dump(corrected_appkeys, f, indent=2)
    
    print(f"✅ Created corrected_appkeys.json")
    print(f"\nKey changes:")
    print(f"  k256_key: {derived_app_key_bytes.hex()}")
    print(f"  k256_signature: {kms_signature.hex()}")
    
    return corrected_appkeys

if __name__ == "__main__":
    main()