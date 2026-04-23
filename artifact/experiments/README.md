# Experiments

This directory contains the measurement and derivation scripts that back the
paper's evaluation claims.

## Primary scripts

- `production-benchmarks.mjs`
  Generates a production-parameter fixture (3072-bit threshold Paillier) and
  measures client-side operations with raw outputs.
- `design-space-comparison.mjs`
  Compiles alternative bridge circuits and derives the quantitative comparison
  table from exact R1CS counts plus explicit gas formulas.
- `binding-overhead.mjs`
  Small structural sanity check for limb count, tree depth, and public-input
  overhead.

## Results

Machine-readable outputs are written to `results/`:

- `production-fixture-3072.json`
- `production-benchmarks.json`
- `contract-gas-benchmarks.json`
- `design-space-comparison.json`

## Commands

```bash
yarn bench:production
yarn gas:bench
yarn design:space
yarn binding:overhead
```
