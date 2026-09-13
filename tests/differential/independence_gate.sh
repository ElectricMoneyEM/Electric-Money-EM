#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="$ROOT/build-independence-gate"
rm -rf "$BUILD"
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$BUILD" -j2 >/dev/null
ctest --test-dir "$BUILD" --output-on-failure
"$BUILD/em_tests"
"$BUILD/em_consensus_vectors"
"$BUILD/em_consensus_transition"
"$BUILD/em_l2_bridge_gate"
# The source tree must contain no V19.2 oracle or oracle build path.
if grep -RIlE --exclude='independence_gate.sh' 'legacy/electric_money_v19_2\.cpp|v19_2|V19\.2 oracle' "$ROOT/include" "$ROOT/src" "$ROOT/tests" "$ROOT/CMakeLists.txt" >/dev/null 2>&1; then
  echo "ORACLE_REFERENCE_FOUND"
  exit 1
fi
echo "ORACLE_INDEPENDENCE_GATE_PASS"
