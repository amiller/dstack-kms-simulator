# DStack Signature Chain Verification

DStack signature chains need verification against the correct KMS root address. This repo provides the infrastructure to debug and verify signatures.

## Quick Debug Setup

### 1. Install Dependencies
```bash
# IMPORTANT: Use Python 3.10 specifically for dstack-sdk compatibility
python3.10 -m venv venv310 && source venv310/bin/activate
pip install -r requirements.txt
npm install -g phala
cd contracts && forge install && forge build
```

### 2. Clone DStack Repository
```bash
# Clone dstack repo to refs/ directory (NOT root directory)
mkdir -p refs && git clone https://github.com/Phala-Network/dstack.git refs/dstack

# Build simulator in refs/dstack/simulator
cd refs/dstack/simulator && ./build.sh
cp -r ./ ../../../simulator
```

**⚠️ Directory Structure**: Keep dstack in `./refs/dstack/` to avoid confusion with contracts directory.

### 3. Test Simulator (Working)
```bash
# Fix broken appkeys and test
python scripts/generate_correct_appkeys.py
cd refs/dstack/simulator && ./dstack-simulator &
# Run from project root, not simulator directory
python scripts/test_dstack_signatures.py  # ✅ PASSES
```

### 4. Test Production with Correct KMS Root
```bash
# Get correct KMS root address from contract
cast call 0x2f83172A49584C017F2B256F0FB2Dca14126Ba9C "kmsInfo()" --rpc-url https://base.llamarpc.com

# Deploy CVM (if not already done)
phala deploy --name "debug-dstack" --node-id 12 --kms-id "kms-base-prod7" --private-key $PRIVATE_KEY --rpc-url https://base.llamarpc.com docker-compose.yml

# Test with correct KMS root
python test_final_verification.py  # ✅ PASSES with 0x52d3CF51c8A37A2CCfC79bBb98c7810d7Dd4CE51
```

## Agent coding Pitfalls & Solutions

### ❌ **Wrong KMS Root Address**
**Pitfall**: Using KMS contract address as the signing key address  
**Reality**: Contract address ≠ signing key address  
**Solution**: Get `k256Pubkey` from contract's `kmsInfo()` and derive the actual address

### ❌ **Directory Navigation Confusion**
**Pitfall**: Running commands from wrong directories, mixing `./contracts/` with root  
**Solution**: 
- Run forge commands from `./contracts/` only  
- Run Python scripts from project root
- Keep dstack repo in `./refs/dstack/`
