# DStack Signature Chain Verification

**Problem**: DStack signature chains generated in Phala CVMs are not verifying correctly in Solidity contracts. This repo provides the infrastructure to debug the issue.

## Current Status ❌

✅ **CVM Deployment**: Successfully generates signature data in Phala Cloud  
✅ **Contract Deployment**: Smart contract deployed and callable on Base  
❌ **Signature Verification**: Contract returns `false` - **THIS IS THE BUG TO FIX**

## Quick Debug Setup

### 1. Install Dependencies
```bash
python3 -m venv venv310 && source venv310/bin/activate
pip install -r requirements.txt
npm install -g phala
cd contracts && forge install && forge build
```

### 2. Test Simulator (Working)
```bash
# Build simulator
git clone https://github.com/Phala-Network/dstack.git /tmp/dstack
cd /tmp/dstack/simulator && ./build.sh
ln -sf /tmp/dstack/simulator/dstack-simulator ./simulator/dstack-simulator
ln -sf /tmp/dstack/simulator/appkeys.json ./simulator/appkeys.json

# Fix broken appkeys and test
python scripts/generate_correct_appkeys.py
cd simulator && ./dstack-simulator &
python scripts/test_dstack_signatures.py  # ✅ PASSES
```

### 3. Test Production (Failing)
```bash
# Deploy contract
cd contracts && forge script script/DeployVerifier.s.sol:DeployVerifier --rpc-url base --private-key $PRIVATE_KEY --broadcast

# Deploy CVM
phala deploy --name "debug-dstack" --vcpu 1 --memory 1024 --disk-size 10 --kms-id "kms-base-prod7" --private-key $PRIVATE_KEY --rpc-url https://base.llamarpc.com docker-compose.yml

# Update test_phala_production.py with your App ID and contract address
python test_phala_production.py  # ❌ Contract returns false
```

## Debug Data Available

The production test outputs:
- **CVM signature data**: Real signatures from Phala Cloud
- **Contract parameters**: Formatted for Solidity call
- **Verification result**: `false` (the bug)

## Investigation Needed

The issue is likely in one of these areas:
1. **Message format mismatch**: CVM vs contract expectations
2. **Signature encoding**: How signatures are passed to contract
3. **App ID formatting**: bytes32 padding or encoding
4. **Recovery logic**: ecrecover implementation differences

## Files
- `test_phala_production.py`: End-to-end test with debug output
- `contracts/src/SimpleDstackVerifier.sol`: Contract verification logic
- `docker-compose.yml`: CVM signature generation
- `scripts/test_dstack_signatures.py`: Working simulator test