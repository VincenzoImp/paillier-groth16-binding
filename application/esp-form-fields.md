# ESP Form Fields Draft

## Project Name

Verifiable Private Governance on Ethereum

## Project Summary

This project studies a reusable mechanism for Ethereum that lets an institution
verify on-chain that an encrypted collective decision is exactly the one
authorized by its corresponding proof, even when the underlying encryption and
proof systems are incompatible. The flagship case is private voting and
committee decisions, using threshold-Paillier for efficient encrypted
aggregation and Groth16 for cheap on-chain verification. The public repository
already contains a working research artifact with a tested acceptance-side
binding mechanism, a real Groth16 verifier, a reproduced attack on the naive
composition, tests, and benchmarks. The proposed research extends that base by
strengthening guarantees around the final aggregate, clarifying which rules are
immutable, adjustable, or discretionary in this governance design, and
producing an open-access paper and public artifact for Ethereum governance
builders. Public work: https://github.com/VincenzoImp/paillier-groth16-binding

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

Cryptography

## Suggested Output Type

Research

## Have You Applied Before To Any Grants At The Ethereum Foundation?

No

## Referral

No

## Additional Questions Or Comments

Happy to provide artifact reproduction details or any supporting material upon request.

## Allow Contact From Ethereum Foundation About Other Opportunities?

Yes

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
