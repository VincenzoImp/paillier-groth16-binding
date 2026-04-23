# ESP Form Fields Draft

## Project Name

Verifiable Private Governance on Ethereum

## Project Summary

This project studies a governance primitive for Ethereum: allowing an
institution to verify on-chain that an encrypted decision is exactly the
decision authorized by its eligibility proof, even when the encryption and
proof systems are cryptographically incompatible. The flagship case is private
collective decision-making using threshold-Paillier encryption for efficient
private aggregation and Groth16 proofs for cheap EVM verification. The
repository already contains a working artifact with a real Groth16 verifier, a
reproduced attack on the naive composition, and benchmarked implementations;
the proposed research strengthens tally-side integrity, formalizes what is
immutable versus adjustable or discretionary in this governance design, and
produces an open-access academic output.

## Project Repo Link

https://github.com/VincenzoImp/paillier-groth16-binding

## Website

https://vincenzo.imperati.dev

## ORCID

https://orcid.org/0009-0001-9437-1384

## Google Scholar

https://scholar.google.com/citations?user=V4XgGVcAAAAJ

## Supervisor

Alessandro Mei — http://wwwusers.di.uniroma1.it/~mei/

## Research Profile

https://research.uniroma1.it/researcher/0f9c3c1227f530e4af686c68b186e30bf4f6679206966e380af17780

## Suggested Domain

Research

## Suggested Output Type

Open-source research artifact and academic paper

## Public Work Links

- Project repository: https://github.com/VincenzoImp/paillier-groth16-binding
- Fellowship proposal PDF: https://github.com/VincenzoImp/paillier-groth16-binding/blob/main/application/ethereum-foundation-phd-fellowship-2026-proposal.pdf

## Notes For Submission

- The proposal track is `Programmable Institutional Design and Verifiable Governance`.
- In the narrative, keep `voting` as the flagship institutional case.
- Mention `federated learning` only as evidence that the mixed-domain pattern
  matters beyond voting; do not present it as a second full deliverable.
- Keep the framing honest: the repository demonstrates a research artifact and
  a desirable blocked design point, not a production exploit against a major
  deployed system.
