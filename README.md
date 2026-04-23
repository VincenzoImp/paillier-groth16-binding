# Paillier-Groth16 Binding

Public artifact repository for research on a missing interoperability layer
between:

- threshold Paillier encryption over `Z*_(N^2)` for private aggregation; and
- Groth16-style succinct proofs over BN254 for cheap verification on Ethereum.

The flagship case study is private collective decision-making on Ethereum:
committee votes, council approvals, sealed governance actions, and similar
workflows where a public system must verify that the encrypted object posted to
the bulletin board is the same object authorized by a succinct proof.

## Why this repository exists

This repository packages the current research artifact into a public,
self-contained form.

The central thesis is:

> when an encrypted object and the proof that authorizes it live in
> incompatible algebraic domains, naive composition is insecure; a binding
> layer is required to make the relation enforceable by code.

In this project:

- `Paillier` is useful in workflows that need additive aggregation over a large
  integer domain and threshold decryption; 
- `Groth16` is practical for on-chain proof verification because of Ethereum's
  BN254 precompiles; and
- their composition is not naturally same-domain, so the interface must be made
  explicit.

This is not a deployment-ready governance product. It is a research artifact
that isolates, implements, and evaluates that mixed-domain acceptance problem.

## What the artifact demonstrates

The public artifact currently demonstrates:

- a Circom statement for eligibility plus ciphertext-limb binding;
- a Solidity bulletin-board contract with a real Groth16 verifier path;
- a reproducible attack/defense path showing why naive composition fails;
- transcript reconstruction and aggregate-consistency utilities;
- contract tests, crypto tests, and benchmark scripts.

The current artifact does **not** claim:

- a complete production e-voting system;
- full end-to-end tally correctness for every tally workflow;
- coercion resistance or receipt-freeness;
- on-chain committee governance or operational orchestration;
- a real-world vulnerability in a major deployed Ethereum governance product.

The point is different: to document and evaluate a design point that is
appealing on Ethereum but awkward to compose cleanly with existing tooling.

## Repository layout

- `artifact/`
  Core research artifact: contracts, circuits, crypto helpers, scripts, and
  experiments.

## Quick start

This repository uses Yarn workspaces.

```bash
yarn install
yarn quick:attack
yarn verify
```

Useful commands:

```bash
yarn quick:attack      # shortest path to the core attack/defense thesis
yarn attack:demo       # script-driven replay
yarn transcript:demo   # transcript reconstruction
yarn gas:bench         # contract gas benchmarks
yarn bench:production  # production-parameter benchmark script
```

## Why Paillier and Groth16

The repository is centered on a specific mixed-domain design point that is easy
to motivate on Ethereum:

- `Paillier` is convenient when encrypted values must support additive
  aggregation over a large integer domain and when threshold decryption is a
  natural fit for the application workflow.
- `Groth16` is convenient on Ethereum because succinct verification is cheap
  relative to many alternatives and maps directly to BN254 precompiles.

If the proof system and the encrypted object lived in the same proof-friendly
domain, this repository would be less interesting. The project matters exactly
because that is not the case here.

## Beyond voting

Private governance is the main case study because it is the clearest
institutional fit for Ethereum's `Programmable Institutional Design and
Verifiable Governance` agenda. But the same pattern can matter more broadly in
encrypted aggregation settings where a public system must verify that an
encrypted update is the one authorized by a proof. That is why the surrounding
research also tracks adjacent domains such as verifiable aggregation workflows
in federated learning.

## License

This repository is released under the MIT License.
