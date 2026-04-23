import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const circuitsDir = path.resolve(import.meta.dirname, "circuits");
const buildDir = path.resolve(import.meta.dirname, "build");
const resultsDir = path.resolve(import.meta.dirname, "results");
const benchmarkPath = path.join(resultsDir, "production-benchmarks.json");
const outputPath = path.join(resultsDir, "design-space-comparison.json");
const snarkjsBin = path.resolve(repoRoot, "artifact/crypto/node_modules/.bin/snarkjs");

const PUBLIC_INPUT_LINEARIZATION_GAS = 6150;

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function compileCircuit(name) {
  ensureDir(buildDir);
  const outDir = path.join(buildDir, name);
  ensureDir(outDir);

  const source = path.join(circuitsDir, `${name}.circom`);
  execFileSync("circom", [source, "--r1cs", "--sym", "-o", outDir], {
    cwd: repoRoot,
    stdio: "pipe",
    encoding: "utf8",
  });

  const r1csPath = path.join(outDir, `${name}.r1cs`);
  const info = execFileSync(snarkjsBin, ["r1cs", "info", r1csPath], {
    cwd: repoRoot,
    stdio: "pipe",
    encoding: "utf8",
  });

  const extract = (label) => {
    const match = info.match(new RegExp(`${label}:\\s+([0-9]+)`));
    if (!match) {
      throw new Error(`Could not parse '${label}' from r1cs info for ${name}`);
    }
    return Number(match[1]);
  };

  return {
    circuit: name,
    nonLinearConstraints: extract("# of Constraints"),
    wires: extract("# of Wires"),
  };
}

function loadMeasuredProofMedian() {
  if (!fs.existsSync(benchmarkPath)) return null;
  const benchmark = JSON.parse(fs.readFileSync(benchmarkPath, "utf8"));
  return benchmark?.proofGeneration?.medianMs ?? null;
}

function round3(value) {
  return Number(value.toFixed(3));
}

function deriveRow({
  name,
  bridgeInfo,
  baseConstraints,
  publicInputs,
  coverageBits,
  securityStatus,
  caveat,
  currentTotalConstraints,
  currentProofMedianMs,
}) {
  const totalConstraints = baseConstraints + bridgeInfo.nonLinearConstraints;
  const verifierLinearizationGas = publicInputs * PUBLIC_INPUT_LINEARIZATION_GAS;
  const proverEstimateMs =
    currentProofMedianMs == null
      ? null
      : round3(currentProofMedianMs * (totalConstraints / currentTotalConstraints));

  return {
    name,
    bridgeConstraints: bridgeInfo.nonLinearConstraints,
    totalConstraints,
    bridgeWires: bridgeInfo.wires,
    publicInputs,
    calldataBytes: publicInputs * 32,
    verifierLinearizationGas,
    coverageBits,
    securityStatus,
    caveat,
    proverEstimateMs,
  };
}

async function main() {
  ensureDir(resultsDir);

  const eligibilityOnly = compileCircuit("EligibilityOnly");
  const poseidon32 = compileCircuit("PoseidonBridge32");
  const poseidon4 = compileCircuit("PoseidonBridge4");
  const sha256 = compileCircuit("Sha256Bridge6144");
  const pedersenChunk = compileCircuit("PedersenChunk256");
  const currentProofMedianMs = loadMeasuredProofMedian();

  const baseConstraints = eligibilityOnly.nonLinearConstraints;
  const currentTotalConstraints = baseConstraints + poseidon32.nonLinearConstraints;

  const rows = [
    deriveRow({
      name: "current full-limb Poseidon bridge",
      bridgeInfo: poseidon32,
      baseConstraints,
      publicInputs: 36,
      coverageBits: 6144,
      securityStatus: "Injective full-coverage decomposition over the canonical 6144-bit ciphertext space",
      caveat: "High public-input count and calldata footprint are the price of board-visible injectivity",
      currentTotalConstraints,
      currentProofMedianMs,
    }),
    deriveRow({
      name: "SHA-256-in-circuit bridge",
      bridgeInfo: sha256,
      baseConstraints,
      publicInputs: 5,
      coverageBits: 6144,
      securityStatus: "Full ciphertext coverage, but security depends on SHA-256 collision resistance and digest packing",
      caveat: "Much lower public-input cost, but the circuit itself becomes very large",
      currentTotalConstraints,
      currentProofMedianMs,
    }),
    deriveRow({
      name: "Pedersen chunk-commit proxy (24 x 256-bit chunks)",
      bridgeInfo: {
        circuit: "PedersenChunk256 × 24",
        nonLinearConstraints: pedersenChunk.nonLinearConstraints * 24,
        wires: pedersenChunk.wires * 24,
      },
      baseConstraints,
      publicInputs: 51,
      coverageBits: 6144,
      securityStatus: "Full coverage only after chunking the ciphertext into 24 Pedersen commitments",
      caveat: "This is the closest measurable same-group proxy, not a drop-in bulletin-board replacement: the board would still need to carry and reconcile 48 public commitment coordinates",
      currentTotalConstraints,
      currentProofMedianMs,
    }),
    deriveRow({
      name: "partial-limb binding (4 limbs)",
      bridgeInfo: poseidon4,
      baseConstraints,
      publicInputs: 8,
      coverageBits: 768,
      securityStatus: "Structurally non-injective on the canonical ciphertext space",
      caveat: "Cheaper because it leaves 5376 bits unauthenticated; the ablation shows concrete prefix ambiguity",
      currentTotalConstraints,
      currentProofMedianMs,
    }),
  ];

  const result = {
    benchmark: "design-space-comparison",
    generatedAt: new Date().toISOString(),
    methodology: {
      baselineCircuit: "EligibilityOnly.circom",
      note: "Constraint counts are exact R1CS counts compiled with circom. Verifier linearization gas is analytical: 6150 gas per public input (ECMUL + ECADD under EIP-196). Prover-time estimates scale the measured current proof median by total constraint ratio.",
    },
    baseline: eligibilityOnly,
    rows,
  };

  fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
