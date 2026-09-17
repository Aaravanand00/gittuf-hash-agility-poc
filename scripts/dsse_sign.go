package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gittuf/gittuf/internal/signerverifier/dsse"
	"github.com/gittuf/gittuf/internal/signerverifier/ssh"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Usage: %s <old_sha1> <new_sha256> <key_path> <output_path>\n", os.Args[0])
		os.Exit(1)
	}
	oldOID := os.Args[1]
	newOID := os.Args[2]
	keyPath := os.Args[3]
	outputPath := os.Args[4]

	att := map[string]interface{}{
		"_type":          "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://gittuf.dev/hash-equivalence/v0.1",
		"subject": []map[string]interface{}{
			{
				"name": "git-commit",
				"digest": map[string]string{
					"sha1":   oldOID,
					"sha256": newOID,
				},
			},
		},
		"predicate": map[string]interface{}{
			"description": "Hash equivalence bridge from SHA-1 to SHA-256",
		},
	}

	signer, err := ssh.NewSignerFromFile(keyPath)
	if err != nil {
		panic(err)
	}

	env, err := dsse.CreateEnvelope(att)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	signedEnv, err := dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		panic(err)
	}

	out, err := json.MarshalIndent(signedEnv, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile(outputPath, out, 0644); err != nil {
		panic(err)
	}
	fmt.Printf("Successfully signed and wrote attestation to %s\n", outputPath)
}
