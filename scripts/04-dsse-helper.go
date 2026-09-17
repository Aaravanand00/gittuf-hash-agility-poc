package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
	"io/ioutil"
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
		fmt.Println("Usage: dsse-helper <pae|envelope|tamper> [args...]")
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

		statementBytes, _ := json.Marshal(statement)
		
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
			keyID := os.Args[4]
			sigFile := os.Args[5]
			
			sigBytes, err := ioutil.ReadFile(sigFile)
			if err != nil {
				panic(err)
			}
			
			b64Sig := base64.StdEncoding.EncodeToString(sigBytes)

			envelope := DSSEEnvelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     base64.StdEncoding.EncodeToString(statementBytes),
				Signatures: []DSSESignature{
					{KeyID: keyID, Sig: b64Sig},
				},
			}
			
			envBytes, _ := json.MarshalIndent(envelope, "", "  ")
			fmt.Println(string(envBytes))
		}
	} else if command == "tamper" {
		if len(os.Args) < 3 {
			panic("Usage: dsse-helper tamper <envelope_file>")
		}
		envBytes, _ := ioutil.ReadFile(os.Args[2])
		var env DSSEEnvelope
		json.Unmarshal(envBytes, &env)
		
		payloadBytes, _ := base64.StdEncoding.DecodeString(env.Payload)
		var statement InTotoStatement
		json.Unmarshal(payloadBytes, &statement)
		
		statement.Subject[1].Digest["sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
		
		tamperedBytes, _ := json.Marshal(statement)
		env.Payload = base64.StdEncoding.EncodeToString(tamperedBytes)
		
		outBytes, _ := json.MarshalIndent(env, "", "  ")
		fmt.Println(string(outBytes))
	}
}
