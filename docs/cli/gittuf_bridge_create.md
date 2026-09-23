## gittuf bridge create

Create a Genesis Bridge record linking SHA-1 and SHA-256 epochs

```
gittuf bridge create [flags]
```

### Options

```
  -h, --help                 help for create
  -o, --output string        Output path for the genesis bridge record (default "genesis-bridge.json")
      --sha1-head string     Tip OID of SHA-1 repository HEAD
      --sha1-rsl string      Tip OID of SHA-1 RSL epoch
      --sha256-head string   Initial tip OID of SHA-256 repository HEAD
      --sha256-rsl string    Initial tip OID of SHA-256 RSL epoch
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

* [gittuf bridge](gittuf_bridge.md)	 - GAP-1 Genesis Bridge tools for cross-epoch verification

