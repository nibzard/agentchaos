// Command apid serves the beta API monolith: governor and evidence
// plane in process, the broker as a separately isolated upstream.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gauntlet/api"
	"gauntlet/control"
	"gauntlet/evidence"
	"gauntlet/governor"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	broker := flag.String("broker", "http://127.0.0.1:8081",
		"upstream effect broker URL")
	compilerDir := flag.String("compiler-dir", "../control-plane",
		"directory containing the gauntlet_compiler Python package")
	authKeys := flag.String("auth-key", "",
		"path to a file of base64url Ed25519 public keys, one per line, "+
			"that verify principal tokens (required; see api/README.md)")
	flag.Parse()

	brokerURL, err := url.Parse(*broker)
	if err != nil {
		log.Fatalf("broker URL: %v", err)
	}
	auth, err := loadAuthenticator(*authKeys)
	if err != nil {
		log.Fatalf("authentication keys: %v", err)
	}

	server := api.New(
		governor.New(nil),
		&evidence.Server{Recorder: evidence.New()},
		control.NewAssurer(),
		api.NewPythonCompiler(*compilerDir),
		brokerURL,
		auth,
	)
	log.Printf("apid listening on %s (broker %s)", *addr, brokerURL)
	log.Fatal(http.ListenAndServe(*addr, server.Handler()))
}

// loadAuthenticator reads one base64url Ed25519 public key per line.
// Several keys rotate with overlap: mint with the new key while the old
// one still verifies.
func loadAuthenticator(path string) (*api.Authenticator, error) {
	if path == "" {
		return nil, fmt.Errorf("-auth-key is required; the API serves nothing without principal token keys")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("key %q is not base64url: %v", line, err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q is %d bytes; an Ed25519 public key is %d",
				line, len(decoded), ed25519.PublicKeySize)
		}
		keys = append(keys, ed25519.PublicKey(decoded))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s carries no keys", path)
	}
	return api.NewAuthenticator(keys...), nil
}
