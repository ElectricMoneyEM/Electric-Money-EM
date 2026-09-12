# Electric Money V19.2 — Verifiable L2/PoH Bridge Consensus Foundation

Electric Money V19.2 is a C++17 reference/prototype implementation derived from V19.1.
It strengthens the L2 bridge by binding deposits and withdrawals to L1 consensus rules.

## V19.2 changes

- Protocol version 19 / dedicated V19.2 network identifier.
- L2 commitments include canonical deposit and withdrawal manifests.
- L2 deposit events are included in the committed L2 state transition.
- L1 deposit claims require a finalized L1 block (`BRIDGE_FINALITY_DEPTH = 6`).
- Duplicate deposit claims are rejected during chain replay.
- L2 withdrawals reduce the committed L2 state and are included in the PoH transition.
- L1 withdrawal releases are consensus-validated against a finalized L2 commitment.
- Withdrawal release IDs are deterministic and act as persistent chain-level nullifiers.
- A release can only debit the canonical L1 bridge balance and credit the exact L2 withdrawal recipient.
- Replaying the same release is rejected.
- Withdrawal commitments can contain zero ordinary L2 transfers while still proving bridge state changes.
- Existing ML-DSA-65, fee burn, annual levy, supply-cap, persistence, and P2P hardening are retained.

## Bridge flow

```text
L1 transfer -> EM_L2_BRIDGE
       |
       | wait 6 L1 confirmations
       v
L2 deposit claim
       |
       v
L2 commitment (state root + PoH + deposit manifest)
       |
       v
L2 withdrawal
       |
       v
L2 commitment containing withdrawal manifest
       |
       | wait 6 L1 confirmations
       v
L1 withdrawal release
       |
       v
L1 bridge balance -> recipient
```

## Verification model

A node independently reconstructs the L2 transition from the commitment:

`pre-state -> finalized deposits -> signed L2 transactions -> withdrawals -> post-state`

It checks the L2 Merkle transaction root, PoH chain, state root and commitment ID.
For deposits, it additionally verifies the referenced L1 transfer and its finality.
For withdrawals, it verifies the finalized commitment, exact claim, recipient and amount,
and rejects any previously released claim.

## Build

Requires OpenSSL 3.5+ with ML-DSA-65 support and json-c.

```bash
g++ -std=c++17 -O2 -pthread electric_money_v19_2.cpp -lcrypto -ljson-c -o electric_money_v19_2
```

Recommended warning build:

```bash
g++ -std=c++17 -O2 -pthread -Wall -Wextra -Wpedantic electric_money_v19_2.cpp -lcrypto -ljson-c -o electric_money_v19_2
```

## Self-test

```bash
./electric_money_v19_2 --self-test
```

The self-test covers ML-DSA-65 signatures, issuance/halving, fee burn, annual levy anchoring,
L2 transition verification, finalized deposit processing, withdrawal commitments, finalized
L1 release, replay protection, and persistence recovery.

## Security status

**Prototype / testnet research code — not mainnet-ready.**

Important remaining work includes formal bridge/reorg specifications, peer Sybil/eclipsing
resistance, production-grade storage, stronger P2P rate limiting, state-proof scalability,
formal or audited validity/fraud proofs, wallet UX, key management, economic simulations,
fuzzing, differential testing, and independent third-party security audits.

The bridge finality depth is a consensus parameter, not a proof of economic finality. A production
network should define its reorganization and finality assumptions explicitly before enabling real
value withdrawals.
