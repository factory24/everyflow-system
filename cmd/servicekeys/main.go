// servicekeys generates the per-service Ed25519 identities used for internal
// service-to-service auth (see pkg/auth/service.go).
//
//	go run ./cmd/servicekeys asset-management edge iam market recharge token transfer user wallet
//
// It prints one SECRET per service (put in that service's Infisical path as
// SERVICE_PRIVATE_KEY) and ONE shared public map (SERVICE_PUBLIC_KEYS) that every
// service gets — public keys are not secret, so that map can live in a ConfigMap.
//
// Keys are printed to stdout and never written to disk; redirect deliberately if
// you want to keep them, and prefer pasting straight into your secret store.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/factory24/everyflow-system/pkg/auth"
)

func main() {
	names := os.Args[1:]
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "usage: servicekeys <service-name>...")
		fmt.Fprintln(os.Stderr, "example: servicekeys asset-management edge iam market recharge token transfer user wallet")
		os.Exit(2)
	}

	pubs := make(map[string]string, len(names))

	fmt.Println("# ── PER-SERVICE SECRETS ───────────────────────────────────────────")
	fmt.Println("# One per service. Store in that service's secret path ONLY.")
	fmt.Println("# Never commit these and never put them in a ConfigMap.")
	fmt.Println()
	for _, n := range names {
		seed, pub, err := auth.GenerateServiceKeypair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "keygen for %q failed: %v\n", n, err)
			os.Exit(1)
		}
		pubs[n] = pub
		fmt.Printf("# %s\nSERVICE_NAME=%s\nSERVICE_PRIVATE_KEY=%s\n\n", n, n, seed)
	}

	blob, err := json.Marshal(pubs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal public keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("# ── SHARED PUBLIC MAP ─────────────────────────────────────────────")
	fmt.Println("# Identical for every service. Public material — a ConfigMap is fine.")
	fmt.Println("# Every service needs this to VERIFY its peers; without an entry here")
	fmt.Println("# a peer's calls are rejected as an unknown service.")
	fmt.Println()
	fmt.Printf("SERVICE_PUBLIC_KEYS=%s\n", blob)
}
