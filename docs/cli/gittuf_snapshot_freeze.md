## gittuf snapshot freeze

Freeze repository state into a signed/anchored snapshot manifest

```
gittuf snapshot freeze [flags]
```

### Options

```
  -b, --bundle string   optional Git bundle path to hash and link in snapshot
  -h, --help            help for freeze
  -k, --key string      SSH public key fingerprint or identity for root commitment
  -o, --output string   path to write the snapshot manifest JSON (default "snapshot-manifest.json")
```

### Options inherited from parent commands

```
      --no-color                     turn off colored output
      --profile                      enable CPU and memory profiling
      --profile-CPU-file string      file to store CPU profile (default "cpu.prof")
      --profile-memory-file string   file to store memory profile (default "memory.prof")
      --verbose                      enable verbose logging
```

### SEE ALSO

* [gittuf snapshot](gittuf_snapshot.md)	 - GAP-1 Hash Agility cryptographic snapshot tools

