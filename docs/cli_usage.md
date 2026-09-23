# Snapshot Command Quick‑Start

This guide shows how to use the new **`gittuf snapshot`** command introduced for GAP‑1 hash‑agility.

## What the command does
- **Freezes** the current repository state into a deterministic SHA‑256 manifest.
- **Optionally verifies** a repository against an existing manifest.

## Basic usage
```bash
# Build the binary (if you haven’t already)
go build -o gittuf.exe .

# Create a snapshot manifest for the current repo
./gittuf snapshot freeze --output snapshot.json

# Verify the repo against a previously created manifest
./gittuf snapshot verify --manifest snapshot.json
```

## Flags
| Flag | Description |
|------|-------------|
| `--output <file>` | Path where the generated manifest will be saved (default: `snapshot.json`). |
| `--manifest <file>` | Path to an existing manifest you want to verify against. |
| `--verbose` | Show detailed verification steps. |

## Example output
```text
✅ Snapshot created successfully
   manifest written to: snapshot.json
   SHA‑256 content hash: a1b2c3d4…
```

```text
🔍 Verifying repository…
✅ All objects match the manifest – repository is untampered.
```

## When to use it
- **Before a hash‑algorithm migration** – capture the exact state of a SHA‑1 repo.
- **Post‑migration audit** – prove that the new SHA‑256 repo matches the original snapshot.

---

# Bridge Command Quick‑Start

The **`gittuf bridge`** command creates a *Genesis Bridge* entry that cryptographically links the last SHA‑1 RSL tip to the first SHA‑256 RSL tip.

## Typical workflow
1. **Generate a snapshot** of your SHA‑1 repository (see above).
2. **Create the bridge** after you have migrated to SHA‑256.

## Commands
```bash
# Create a bridge entry (writes JSON to bridge.json)
./gittuf bridge create --snapshot snapshot.json --output bridge.json

# Verify the bridge entry later
./gittuf bridge verify --bridge bridge.json
```

## Flags
| Flag | Description |
|------|-------------|
| `--snapshot <file>` | Path to the snapshot manifest that will be linked. |
| `--output <file>`   | Where to write the bridge JSON (default: `bridge.json`). |
| `--verbose`         | Show step‑by‑step verification details. |

## Example output
```text
✅ Genesis Bridge created
   bridge written to: bridge.json
   commitment digest: f1e2d3c4…
```

```text
🔍 Verifying bridge…
✅ Bridge digest matches snapshot and RSL tip – cross‑epoch trust is intact.
```

## Why you need it
- Guarantees **continuous trust** across the migration boundary.
- Enables auditors to follow the RSL from the old SHA‑1 epoch into the new SHA‑256 epoch without breaking the chain of signatures.

---

# 🚀 Automated End-to-End Migration Demo

To see the complete SHA-1 to SHA-256 migration and continuous trust verification in action with a single command:

```bash
./examples/migrate_demo.sh
```

This automated demo:
1. Generates ephemeral Ed25519 signing keys.
2. Initializes a baseline SHA-1 repository with enforced Gittuf policies and RSL entries.
3. Freezes repository state into a deterministic content-level SHA-256 snapshot manifest.
4. Fast-exports Git objects into a fresh native SHA-256 repository.
5. Constructs a Genesis Bridge binding the cryptographic epochs together.
6. Runs full cryptographic verification of the snapshot manifest and Genesis Bridge.
