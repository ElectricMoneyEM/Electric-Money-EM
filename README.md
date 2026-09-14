# Electric Money (EM) — V20.7.6 Oracle  Removed

Electric Money (EM) is an experimental blockchain project. V20.7.6 removes the
V19.2 monolithic oracle after the modular implementation passed the available
deterministic consensus, state-transition, persistence/reorg, and L2/bridge
verification gates.

**NOT production/mainnet cryptocurrency software. Do not use for real funds.**

## Core protocol targets
- SHA3-512 hashing
- ML-DSA-65 post-quantum wallet signatures (OpenSSL 3.5+)
- 25 EM initial block reward
- 1,445,400-block halving interval
- 600-second target block time
- 144-block difficulty interval
- 0.25% incoming payment levy: 0.20% treasury + 0.05% burn
- 0.25% annual wallet balance levy: 0.20% treasury + 0.05% burn
- PoH-based Layer 2 foundation
- bridge finality depth of 6 blocks

## Architecture
`common` · `wallet` · `transaction` · `mining` · `block` · `blockchain` ·
`l2` · `network` · `bridge` · `app`

Public interfaces are in `include/em/`; implementations are in `src/*.cpp`.
There is no `legacy/` oracle dependency.

## V20.7.6 verification
- Modular CMake build: PASS
- Release CTest: PASS
- Self-test: PASS
- Consensus vectors: PASS
- Consensus-transition tests: PASS
- L2/bridge gate: PASS
- ASan/UBSan gate inherited from V20.7.5: PASS
- Oracle source: REMOVED
- Oracle build path: REMOVED
- Source-tree oracle-reference scan: PASS

## Security status
**NOT MAINNET READY.** Removal of the oracle does not constitute a security
audit or proof of consensus correctness. External review, broader fuzzing,
fault-injection, adversarial P2P testing, economic simulations, and public
testnet testing remain necessary.
