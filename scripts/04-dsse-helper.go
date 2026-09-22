package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type InTotoStatement struct {
	Type          string                 `json:"_type"`
	Subject       []InTotoSubject        `json:"subject"`
	PredicateType string                 `json:"predicateType"`
	Predicate     HashEquivalencePayload `json:"predicate"`
}

type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type HashEquivalencePayload struct {
	EpochTransition   string    `json:"epoch_transition"`
	SourceAlgorithm   string    `json:"source_algorithm"`
	TargetAlgorithm   string    `json:"target_algorithm"`
	CertifiedAt       time.Time `json:"certified_at"`
	CertifiedBy       string    `json:"certified_by"`
	VerificationNotes string    `json:"verification_notes"`
}

type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: dsse-helper <pae|envelope|payload|tamper> [args...]")
		os.Exit(1)
	}

	command := os.Args[1]

	if command == "pae" || command == "envelope" || command == "payload" {
		if len(os.Args) < 4 {
			fmt.Println("Usage: dsse-helper pae|envelope|payload <sha1> <sha256> [keyID] [sigFile]")
			os.Exit(1)
		}
		sha1Head := os.Args[2]
		sha256Head := os.Args[3]

		statement := InTotoStatement{
			Type: "https://in-toto.io/Statement/v1",
			Subject: []InTotoSubject{
				{Name: "git-commit-epoch-source", Digest: map[string]string{"sha1": sha1Head}},
				{Name: "git-commit-epoch-target", Digest: map[string]string{"sha256": sha256Head}},
			},
			PredicateType: "https://gittuf.dev/predicate/hash-equivalence/v1",
			Predicate: HashEquivalencePayload{
				EpochTransition:   "sha1-to-sha256",
				SourceAlgorithm:   "sha1",
				TargetAlgorithm:   "sha256",
				CertifiedAt:       time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC),
				CertifiedBy:       "maintainer-key (SSH / Sigstore Fulcio)",
				VerificationNotes: "Certified via gittuf GAP-1 hash migration tool. Cryptographic tree identity validated.",
			},
		}

		statementBytes, err := json.Marshal(statement)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling statement: %v\n", err)
			os.Exit(1)
		}

		if command == "payload" {
			fmt.Print(string(statementBytes))
			return
		}

		pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len("application/vnd.in-toto+json"), "application/vnd.in-toto+json", len(statementBytes), string(statementBytes))

		if command == "pae" {
			fmt.Print(pae)
			return
		}

		if command == "envelope" {
			if len(os.Args) < 6 {
				fmt.Println("Usage: dsse-helper envelope <sha1> <sha256> <keyID> <sigFile>")
				os.Exit(1)
			}
			keyID := os.Args[4]
			sigFile := os.Args[5]

			sigBytes, err := os.ReadFile(sigFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading sig file: %v\n", err)
				os.Exit(1)
			}

			b64Sig := base64.StdEncoding.EncodeToString(sigBytes)

			envelope := DSSEEnvelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     base64.StdEncoding.EncodeToString(statementBytes),
				Signatures: []DSSESignature{
					{KeyID: keyID, Sig: b64Sig},
				},
			}

			envBytes, err := json.MarshalIndent(envelope, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling envelope: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(envBytes))
		}
	} else if command == "tamper" {
		if len(os.Args) < 3 {
			fmt.Println("Usage: dsse-helper tamper <envelope_file>")
			os.Exit(1)
		}
		envBytes, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading envelope: %v\n", err)
			os.Exit(1)
		}
		var env DSSEEnvelope
		if err := json.Unmarshal(envBytes, &env); err != nil {
			fmt.Fprintf(os.Stderr, "Error unmarshaling envelope: %v\n", err)
			os.Exit(1)
		}

		payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding payload: %v\n", err)
			os.Exit(1)
		}
		var statement InTotoStatement
		if err := json.Unmarshal(payloadBytes, &statement); err != nil {
			fmt.Fprintf(os.Stderr, "Error unmarshaling statement: %v\n", err)
			os.Exit(1)
		}

		if len(statement.Subject) > 1 {
			statement.Subject[1].Digest["sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
		}

		tamperedBytes, err := json.Marshal(statement)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling tampered statement: %v\n", err)
			os.Exit(1)
		}
		env.Payload = base64.StdEncoding.EncodeToString(tamperedBytes)

		outBytes, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling tampered envelope: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(outBytes))
	} else if command == "extract" {
		if len(os.Args) < 5 {
			fmt.Println("Usage: dsse-helper extract <envelope_file> <sig_out> <payload_out>")
			os.Exit(1)
		}
		envBytes, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading envelope: %v\n", err)
			os.Exit(1)
		}
		var env DSSEEnvelope
		if err := json.Unmarshal(envBytes, &env); err != nil {
			fmt.Fprintf(os.Stderr, "Error unmarshaling envelope: %v\n", err)
			os.Exit(1)
		}

		if len(env.Signatures) > 0 {
			sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
			if err == nil {
				os.WriteFile(os.Args[3], sigBytes, 0644)
			}
		}

		payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
		if err == nil {
			os.WriteFile(os.Args[4], payloadBytes, 0644)
		}
	}
}
