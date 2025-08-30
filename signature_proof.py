#!/usr/bin/env python3
"""
DStack Signature Chain Verification

Simplified module for verifying DStack signature chains that prove:
1. App Key signed the derived key
2. KMS Root signed the app key 
"""

import hashlib
import os
from dataclasses import dataclass
from dstack_sdk import DstackClient
from eth_account import Account
from eth_utils import keccak
from eth_keys import keys

@dataclass
class SignatureProof:
    """Complete signature chain proof"""
    derived_private_key: bytes
    app_signature: bytes  # App signs derived key
    kms_signature: bytes  # KMS signs app key
    purpose: str
    app_id: str

class SignatureProofGenerator:
    """Generates and verifies DStack signature chain proofs"""
    
    def __init__(self, dstack_socket: str = None):
        # Default to production socket, fallback to simulator
        if dstack_socket is None:
            if os.path.exists('/var/run/dstack.sock'):
                dstack_socket = '/var/run/dstack.sock'
            else:
                dstack_socket = './simulator/dstack.sock'
        self.client = DstackClient(dstack_socket)
    
    def generate_proof(self, key_path: str, purpose: str = "mainnet") -> SignatureProof:
        """Generate complete signature chain proof"""
        # Get key and signature chain from DStack
        key_response = self.client.get_key(key_path, purpose)
        info = self.client.info()
        
        # Extract components
        derived_private_key = bytes.fromhex(key_response.key.replace('0x', ''))
        app_signature = bytes.fromhex(key_response.signature_chain[0].replace('0x', ''))
        kms_signature = bytes.fromhex(key_response.signature_chain[1].replace('0x', ''))
        
        return SignatureProof(
            derived_private_key=derived_private_key,
            app_signature=app_signature,
            kms_signature=kms_signature,
            purpose=purpose,
            app_id=info.app_id
        )
    
    def verify_proof(self, proof: SignatureProof, expected_kms_root: str) -> bool:
        """
        Verify complete signature chain
        
        Returns True if:
        1. App key correctly signed the derived key
        2. KMS root correctly signed the app key
        """
        try:
            # Step 1: Verify app key signed derived key
            # Message format: "{purpose}:{derived_pubkey_sec1_hex}"
            derived_public_key = keys.PrivateKey(proof.derived_private_key).public_key
            derived_pubkey_sec1 = derived_public_key.to_compressed_bytes()
            app_message = f"{proof.purpose}:{derived_pubkey_sec1.hex()}"
            app_message_hash = keccak(text=app_message)
            
            app_signer = Account._recover_hash(app_message_hash, signature=proof.app_signature)
            
            # Step 2: Verify KMS signed app key  
            # Message format: "dstack-kms-issued:{app_id_bytes}{app_pubkey_sec1}"
            app_id_bytes = bytes.fromhex(proof.app_id.replace('0x', ''))
            
            # Get app public key from recovered app signer
            app_signature_obj = keys.Signature(proof.app_signature)
            app_pubkey_sec1 = app_signature_obj.recover_public_key_from_msg_hash(app_message_hash).to_compressed_bytes()
            
            kms_message = b"dstack-kms-issued:" + app_id_bytes + app_pubkey_sec1
            kms_message_hash = keccak(kms_message)
            
            kms_signer = Account._recover_hash(kms_message_hash, signature=proof.kms_signature)
            
            # Verify against expected KMS root
            return kms_signer.lower() == expected_kms_root.lower()
            
        except Exception as e:
            print(f"Verification failed: {e}")
            return False

