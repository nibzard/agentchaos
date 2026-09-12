// Command brokerd serves the effect broker's HTTP tool interface.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"gauntlet/broker"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8081", "listen address")
	policyPath := flag.String("policy", "", "path to a BrokerPolicy document")
	flag.Parse()

	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}

	policyData := broker.DefaultPolicyJSON
	if *policyPath != "" {
		data, err := os.ReadFile(*policyPath)
		if err != nil {
			log.Fatalf("read policy: %v", err)
		}
		policyData = data
	}
	policy, err := broker.LoadPolicy(policyData)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}

	service := broker.New(policy, nil, []broker.Sink{&broker.SyntheticSink{}})
	server := &broker.Server{Broker: service}

	log.Printf("brokerd listening on %s (policy %s, %s)", *addr,
		policy.Version, policyDigest(policy))
	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		log.Fatal(err)
	}
}

func policyDigest(policy *broker.Policy) string {
	digest, err := policy.Digest()
	if err != nil {
		return "unavailable"
	}
	return digest
}
