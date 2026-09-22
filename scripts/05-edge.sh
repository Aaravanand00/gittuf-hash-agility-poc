#!/bin/bash
set +e

echo "=== Phase 4: Edge Cases Probes ==="

echo "--------------------------------------------------------"
echo "PROBE 1: compatObjectFormat Window"
echo "--------------------------------------------------------"
echo "HYPOTHESIS: Git will resolve OLD 40-char OIDs, but gittuf will fail because the old OIDs embedded in the commit messages won't match the new SHA-256 identities of the target commits."

rm -rf work/new-repo-compat
git init --object-format=sha256 work/new-repo-compat
git -C work/new-repo-compat config extensions.compatObjectFormat sha1

# fast-import from old-repo
git -C work/old-repo fast-export --all --signed-tags=strip | git -C work/new-repo-compat fast-import > /dev/null

if git -C work/new-repo-compat fetch ../old-repo "refs/gittuf/*:refs/gittuf/*" 2>/dev/null; then
  echo "RESULT 1.1: Fetch SUCCEEDED with compatObjectFormat!"
else
  echo "RESULT 1.1: Fetch FAILED even with compatObjectFormat!"
  # Natively copy refs if fetch fails
  cp -r work/old-repo/.git/refs/gittuf work/new-repo-compat/.git/refs/
fi

OLD_HEAD=$(git -C work/old-repo rev-parse main)
echo "Checking if git cat-file -p $OLD_HEAD works in compat repo..."
if git -C work/new-repo-compat cat-file -p $OLD_HEAD > /dev/null 2>&1; then
  echo "RESULT 1.2: Git successfully resolved the old SHA-1 OID natively!"
else
  echo "RESULT 1.2: Git could NOT resolve the old SHA-1 OID natively."
fi

echo "Running gittuf verify-ref..."
pushd work/new-repo-compat >/dev/null
if gittuf verify-ref --verbose main > ../probe1-gittuf.txt 2>&1; then
  popd >/dev/null
  echo "RESULT 1.3: gittuf verify-ref PASSED (FAIL-OPEN / UNEXPECTED)"
else
  popd >/dev/null
  echo "RESULT 1.3: gittuf verify-ref FAILED (FAIL-CLOSED / EXPECTED)"
  cat work/probe1-gittuf.txt | grep -i "error" | head -n 3
fi

echo "--------------------------------------------------------"
echo "PROBE 2: Fresh-Clone Verification"
echo "--------------------------------------------------------"
echo "HYPOTHESIS: Cloning the fresh SHA-256 repo will succeed and verify cleanly, confirming state is portable."
rm -rf work/new-repo-fresh-clone
git clone work/new-repo-fresh work/new-repo-fresh-clone > /dev/null 2>&1
pushd work/new-repo-fresh-clone >/dev/null
if gittuf verify-ref --verbose main > /dev/null 2>&1; then
  popd >/dev/null
  echo "RESULT 2: Clone verification PASSED."
else
  popd >/dev/null
  echo "RESULT 2: Clone verification FAILED."
fi

echo "--------------------------------------------------------"
echo "PROBE 3: Retaining Signed Tags in SHA-256"
echo "--------------------------------------------------------"
echo "HYPOTHESIS: git fast-export without --signed-tags=strip will fail during import, or silently strip the signature, because the signature is over the SHA-1 text."
rm -rf work/new-repo-signedtags
git init --object-format=sha256 work/new-repo-signedtags
if git -C work/old-repo fast-export --all | git -C work/new-repo-signedtags fast-import > /dev/null 2> work/probe3-err.txt; then
  echo "RESULT 3: Import succeeded. Checking tag signature..."
  # Check tag v1.0.0
  git -C work/new-repo-signedtags verify-tag v1.0.0 2> work/probe3-verify.txt || git -C work/new-repo-signedtags verify-tag v1.0 2> work/probe3-verify.txt || true
  cat work/probe3-verify.txt
else
  echo "RESULT 3: Import FAILED:"
  cat work/probe3-err.txt
fi

echo "--------------------------------------------------------"
echo "PROBE 4: Snapshot Determinism"
echo "--------------------------------------------------------"
echo "HYPOTHESIS: Re-running the commitment script on a fresh clone of the bundle will yield the exact same SHA-256 hash."
rm -rf work/old-repo-audit
git clone --mirror archives/old-repo.bundle work/old-repo-audit > /dev/null 2>&1

{
  git -C work/old-repo-audit show-ref --heads --tags | awk '{print $1}'
  git -C work/old-repo-audit rev-parse refs/gittuf/reference-state-log 2>/dev/null || echo ""
  git -C work/old-repo-audit rev-parse refs/gittuf/policy 2>/dev/null || echo ""
  ssh-keygen -l -f keys/root.pub | awk '{print $2}'
} | sed '/^$/d' | LC_ALL=C sort -u > work/probe4-commitment.txt

NEW_COMMITMENT=$(sha256sum work/probe4-commitment.txt | awk '{print $1}')
MANIFEST_COMMITMENT=$(grep -o '"commitment_sha256": *"[^"]*"' archives/snapshot-manifest.json | head -1 | cut -d'"' -f4)

if [ "$NEW_COMMITMENT" == "$MANIFEST_COMMITMENT" ]; then
  echo "RESULT 4: Determinism verified! Hash matches: $NEW_COMMITMENT"
else
  echo "RESULT 4: Determinism FAILED! New: $NEW_COMMITMENT vs Manifest: $MANIFEST_COMMITMENT"
fi

echo "=== Phase 4 Completed ==="