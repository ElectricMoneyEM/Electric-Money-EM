# Differential directory — post-oracle verification

V20.7.6 no longer contains the former reference implementation. The previous legacy-vs-modular
comparison harness has been retired.

`independence_gate.sh` verifies that the modular tree builds and all currently
registered consensus, transition, L2/bridge, self-test and hardening tests pass,
and that no source/documentation references to the removed oracle remain.

This is an independence/regression gate, not a formal proof of consensus
correctness or mainnet readiness.
