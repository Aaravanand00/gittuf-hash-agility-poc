#!/bin/bash
set -e

# Parse arguments
SKIP_PHASE_0=0
SKIP_PHASE_1=0
SKIP_PHASE_2=0
SKIP_PHASE_3=0
SKIP_PHASE_4=0

for arg in "$@"; do
  case $arg in
    --skip-phase-0) SKIP_PHASE_0=1 ;;
    --skip-phase-1) SKIP_PHASE_1=1 ;;
    --skip-phase-2) SKIP_PHASE_2=1 ;;
    --skip-phase-3) SKIP_PHASE_3=1 ;;
    --skip-phase-4) SKIP_PHASE_4=1 ;;
  esac
done

echo "=============================================="
echo " Gittuf GAP-1 Hash Agility Proof of Concept"
echo "=============================================="

if [ $SKIP_PHASE_0 -eq 0 ]; then
  echo "-> Running Phase 0: Environment Setup"
  bash scripts/00-env.sh
else
  echo "-> Skipping Phase 0"
fi

if [ $SKIP_PHASE_1 -eq 0 ]; then
  echo "-> Running Phase 1: Baseline SHA-1 Setup & Freeze Snapshot"
  bash scripts/01-baseline.sh
  bash scripts/02-freeze-snapshot.sh
else
  echo "-> Skipping Phase 1"
fi

if [ $SKIP_PHASE_2 -eq 0 ]; then
  echo "-> Running Phase 2: Verification Matrix"
  bash scripts/03-verification-matrix.sh
else
  echo "-> Skipping Phase 2"
fi

if [ $SKIP_PHASE_3 -eq 0 ]; then
  echo "-> Running Phase 3: Hash-Equivalence Attestation"
  bash scripts/04-attestation.sh > results/04-attestation.txt 2>&1
  cat results/04-attestation.txt
else
  echo "-> Skipping Phase 3"
fi

if [ $SKIP_PHASE_4 -eq 0 ]; then
  echo "-> Running Phase 4: Edge Cases Probes"
  bash scripts/05-edge.sh > results/05-edge.txt 2>&1
  cat results/05-edge.txt
else
  echo "-> Skipping Phase 4"
fi

echo "=============================================="
echo " All phases completed successfully."
echo " Check the results/ directory for raw outputs."
echo "=============================================="
