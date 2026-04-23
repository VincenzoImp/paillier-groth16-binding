# Circuits

Circom circuit for the cross-group binding construction.

## CrossGroupBallot.circom

Combines four constraint blocks:

1. **Leaf construction**: `Poseidon(address, secret)`
2. **Merkle membership**: depth-10 Poseidon tree
3. **Nullifier relation**: `Poseidon(secret, nullifierDomain)`
4. **Ciphertext binding**: 32 × 192-bit limbs range-checked and hashed via depth-5 Poseidon tree

### Circuit Parameters

| Parameter | Value |
|---|---|
| Non-linear constraints | 16,494 |
| Wires | 16,508 |
| Public inputs | 36 |
| Private inputs | 22 |
| Curve | BN128 (BN254) |

### Build Artifacts

The `build/` directory contains:

- `CrossGroupBallot.r1cs` — R1CS constraint system
- `CrossGroupBallot.sym` — symbol table
- `CrossGroupBallot_js/CrossGroupBallot.wasm` — WASM witness calculator
- `pot15.ptau` — Powers of Tau (Hermez, power 15)
- `circuit_final.zkey` — Groth16 proving key
- `verification_key.json` — verification key
- `Groth16Verifier.sol` — Solidity verifier (also in `contracts/src/`)

### Rebuild Pipeline

```bash
# 1. Compile circuit
circom CrossGroupBallot.circom --r1cs --wasm --sym -o build/

# 2. Download ptau (if not present)
curl -sL "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau" -o build/pot15.ptau

# 3. Groth16 setup + verifier export
cd build
npx snarkjs groth16 setup CrossGroupBallot.r1cs pot15.ptau circuit_0000.zkey
npx snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="lab" -e="cgbl"
npx snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
npx snarkjs zkey export solidityverifier circuit_final.zkey Groth16Verifier.sol

# 4. Copy verifier to contracts
cp Groth16Verifier.sol ../../contracts/src/Groth16Verifier.sol
```
