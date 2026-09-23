#!/usr/bin/env bash
# ==============================================================================
# Script: examples/migrate_demo.sh
# Purpose: Interactive, automated End-to-End demonstration of GAP-1 Hash Agility
#          migrating a repository from SHA-1 to SHA-256 with continuous trust.
# ==============================================================================

set -euo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

echo -e "${BOLD}${BLUE}======================================================================${RESET}"
echo -e "${BOLD}${CYAN}   GITTUF GAP-1 HASH AGILITY: END-TO-END MIGRATION DEMO (SHA-1 ➔ SHA-256)   ${RESET}"
echo -e "${BOLD}${BLUE}======================================================================${RESET}"
echo

# 0. Setup Temporary Working Directory
DEMO_ROOT="$(mktemp -d -t gittuf-demo-XXXXXX)"
trap 'rm -rf "${DEMO_ROOT}"' EXIT

KEYS_DIR="${DEMO_ROOT}/keys"
SRC_REPO="${DEMO_ROOT}/repo-sha1"
DST_REPO="${DEMO_ROOT}/repo-sha256"
MANIFEST_FILE="${DEMO_ROOT}/snapshot-manifest.json"
BRIDGE_FILE="${DEMO_ROOT}/genesis-bridge.json"

mkdir -p "${KEYS_DIR}" "${SRC_REPO}" "${DST_REPO}"

# Locate gittuf binary
GITTUF_BIN="$(command -v gittuf 2>/dev/null || true)"
if [ -z "${GITTUF_BIN}" ]; then
    CURRENT_USER="${USER:-${USERNAME:-}}"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    POC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
    for candidate in \
        "${POC_DIR}/gittuf" \
        "${POC_DIR}/gittuf.exe" \
        "${HOME}/go/bin/gittuf" \
        "${HOME}/go/bin/gittuf.exe" \
        "/c/Users/${CURRENT_USER}/go/bin/gittuf.exe" \
        "/mnt/c/Users/${CURRENT_USER}/go/bin/gittuf.exe"; do
        if [ -n "${candidate}" ] && [ -f "${candidate}" ]; then
            GITTUF_BIN="${candidate}"
            break
        fi
    done
fi

if [ -z "${GITTUF_BIN}" ]; then
    echo -e "${YELLOW}Building gittuf binary for demo...${RESET}"
    go build -o "${DEMO_ROOT}/gittuf" .
    GITTUF_BIN="${DEMO_ROOT}/gittuf"
fi

echo -e "${GREEN}✔ Using Gittuf Binary:${RESET} ${GITTUF_BIN}"
echo

# ------------------------------------------------------------------------------
# STEP 1: Generate Developer and Root Keys
# ------------------------------------------------------------------------------
echo -e "${BOLD}▶ [1/6] Generating cryptographic Ed25519 signing keys...${RESET}"
ssh-keygen -t ed25519 -N "" -f "${KEYS_DIR}/root" -C "root@demo.gittuf" >/dev/null 2>&1
ssh-keygen -t ed25519 -N "" -f "${KEYS_DIR}/policy" -C "policy@demo.gittuf" >/dev/null 2>&1
ssh-keygen -t ed25519 -N "" -f "${KEYS_DIR}/dev" -C "developer@demo.gittuf" >/dev/null 2>&1
ROOT_FP="$(ssh-keygen -l -f "${KEYS_DIR}/root.pub" | awk '{print $2}')"
echo -e "${GREEN}✔ Root Key Fingerprint:${RESET} ${ROOT_FP}"
echo

# ------------------------------------------------------------------------------
# STEP 2: Initialize Baseline SHA-1 Repository with Gittuf Policy & RSL
# ------------------------------------------------------------------------------
echo -e "${BOLD}▶ [2/6] Initializing baseline SHA-1 repository with Gittuf policies...${RESET}"
cd "${SRC_REPO}"
git init -b main >/dev/null 2>&1
git config user.name "Demo Developer"
git config user.email "dev@demo.gittuf"
git config gpg.format ssh
git config user.signingkey "${KEYS_DIR}/dev.pub"

echo "Hello Gittuf GAP-1" > README.md
git add README.md
git commit -m "Initial commit under SHA-1" >/dev/null 2>&1

"${GITTUF_BIN}" trust init -k "${KEYS_DIR}/root" --create-rsl-entry >/dev/null 2>&1
"${GITTUF_BIN}" trust add-policy-key -k "${KEYS_DIR}/root" --policy-key "${KEYS_DIR}/policy.pub" --create-rsl-entry >/dev/null 2>&1
"${GITTUF_BIN}" policy init -k "${KEYS_DIR}/policy" --create-rsl-entry >/dev/null 2>&1
"${GITTUF_BIN}" policy add-key -k "${KEYS_DIR}/policy" --public-key "${KEYS_DIR}/dev.pub" --create-rsl-entry >/dev/null 2>&1

DEV_KEY_ID="$("${GITTUF_BIN}" policy list-principals --policy-ref policy-staging 2>/dev/null | grep -o 'SHA256:[^ :]*' | head -n1 || true)"
"${GITTUF_BIN}" policy add-rule -k "${KEYS_DIR}/policy" --rule-name protect-main --rule-pattern "refs/heads/main" --authorize "${DEV_KEY_ID}" --create-rsl-entry >/dev/null 2>&1
"${GITTUF_BIN}" policy apply -k "${KEYS_DIR}/policy" --local-only >/dev/null 2>&1

echo "Feature commit" > feature.txt
git add feature.txt
git commit -m "Add core feature" >/dev/null 2>&1
"${GITTUF_BIN}" rsl record main --local-only >/dev/null 2>&1

SHA1_HEAD="$(git rev-parse HEAD)"
SHA1_RSL_TIP="$(git rev-parse refs/gittuf/reference-state-log)"
echo -e "   • SHA-1 HEAD OID:    ${CYAN}${SHA1_HEAD}${RESET}"
echo -e "   • SHA-1 RSL Tip OID: ${CYAN}${SHA1_RSL_TIP}${RESET}"
echo -e "${GREEN}✔ Verification in SHA-1 repo:${RESET} $("${GITTUF_BIN}" verify-ref main >/dev/null 2>&1 && echo "PASS (Policy Enforced)" || echo "FAIL")"
echo

# ------------------------------------------------------------------------------
# STEP 3: Create GAP-1 Deterministic Freeze Snapshot (Patrick P2)
# ------------------------------------------------------------------------------
echo -e "${BOLD}▶ [3/6] Freezing SHA-1 repository with deterministic content SHA-256...${RESET}"
"${GITTUF_BIN}" snapshot freeze -o "${MANIFEST_FILE}" -k "${ROOT_FP}" >/dev/null 2>&1
echo -e "${GREEN}✔ Snapshot Manifest Generated:${RESET} ${MANIFEST_FILE}"
grep -E '(sha1_repo_head|content_sha256|commitment_sha256)' "${MANIFEST_FILE}" | sed 's/^/   /'
echo

# ------------------------------------------------------------------------------
# STEP 4: Fast-Export & Fast-Import into SHA-256 Object Format
# ------------------------------------------------------------------------------
echo -e "${BOLD}▶ [4/6] Migrating Git object store from SHA-1 to native SHA-256...${RESET}"
cd "${DST_REPO}"
git init --object-format=sha256 -b main >/dev/null 2>&1
git config user.name "Demo Developer"
git config user.email "dev@demo.gittuf"
git config gpg.format ssh
git config user.signingkey "${KEYS_DIR}/dev.pub"

(cd "${SRC_REPO}" && git fast-export --all --signed-tags=strip) | git fast-import >/dev/null 2>&1
git for-each-ref --format="%(refname)" refs/gittuf/ | while read ref; do git update-ref -d "$ref"; done || true

# Initialize fresh trust in SHA-256 epoch
"${GITTUF_BIN}" trust init -k "${KEYS_DIR}/root" --create-rsl-entry >/dev/null 2>&1
"${GITTUF_BIN}" trust add-policy-key -k "${KEYS_DIR}/root" --policy-key "${KEYS_DIR}/policy.pub" --create-rsl-entry >/dev/null 2>&1
"${GITTUF_BIN}" policy init -k "${KEYS_DIR}/policy" --create-rsl-entry >/dev/null 2>&1
"${GITTUF_BIN}" policy add-key -k "${KEYS_DIR}/policy" --public-key "${KEYS_DIR}/dev.pub" --create-rsl-entry >/dev/null 2>&1
DEV_KEY_ID_DST="$("${GITTUF_BIN}" policy list-principals --policy-ref policy-staging 2>/dev/null | grep -o 'SHA256:[^ :]*' | head -n1 || true)"
"${GITTUF_BIN}" policy add-rule -k "${KEYS_DIR}/policy" --rule-name protect-main --rule-pattern "refs/heads/main" --authorize "${DEV_KEY_ID_DST}" --create-rsl-entry >/dev/null 2>&1
"${GITTUF_BIN}" policy apply -k "${KEYS_DIR}/policy" --local-only >/dev/null 2>&1
"${GITTUF_BIN}" rsl record main --local-only >/dev/null 2>&1

SHA256_HEAD="$(git rev-parse HEAD)"
SHA256_RSL_TIP="$(git rev-parse refs/gittuf/reference-state-log)"
echo -e "   • SHA-256 HEAD OID:    ${CYAN}${SHA256_HEAD}${RESET}"
echo -e "   • SHA-256 RSL Tip OID: ${CYAN}${SHA256_RSL_TIP}${RESET}"
echo -e "${GREEN}✔ Repository format:${RESET} $(git rev-parse --show-object-format)"
echo

# ------------------------------------------------------------------------------
# STEP 5: Create Genesis Bridge Record Linking SHA-1 and SHA-256 Epochs
# ------------------------------------------------------------------------------
echo -e "${BOLD}▶ [5/6] Constructing Genesis Bridge across cryptographic epochs...${RESET}"
"${GITTUF_BIN}" bridge create \
    --sha1-rsl "${SHA1_RSL_TIP}" \
    --sha1-head "${SHA1_HEAD}" \
    --sha256-rsl "${SHA256_RSL_TIP}" \
    --sha256-head "${SHA256_HEAD}" \
    --output "${BRIDGE_FILE}" >/dev/null 2>&1
echo -e "${GREEN}✔ Genesis Bridge Created:${RESET} ${BRIDGE_FILE}"
grep -E '(sha1_rsl_tip|sha256_rsl_tip|commitment_digest)' "${BRIDGE_FILE}" | sed 's/^/   /'
echo

# ------------------------------------------------------------------------------
# STEP 6: Full Verification of Snapshot and Genesis Bridge
# ------------------------------------------------------------------------------
echo -e "${BOLD}▶ [6/6] Verifying Snapshot & Genesis Bridge integrity...${RESET}"
cd "${SRC_REPO}"
"${GITTUF_BIN}" snapshot verify -m "${MANIFEST_FILE}"
"${GITTUF_BIN}" bridge verify -f "${BRIDGE_FILE}"

echo
echo -e "${BOLD}${GREEN}======================================================================${RESET}"
echo -e "${BOLD}${GREEN}   ✔ GAP-1 HASH AGILITY MIGRATION COMPLETED SUCCESSFULLY!            ${RESET}"
echo -e "${BOLD}${GREEN}   ✔ Continuous Chain of Trust Preserved from SHA-1 to SHA-256       ${RESET}"
echo -e "${BOLD}${GREEN}======================================================================${RESET}"
