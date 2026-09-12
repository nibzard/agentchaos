// Command apid serves the beta API monolith: governor and evidence
// plane in process, the broker as a separately isolated upstream.
package main

import (
	"flag"
	"log"
	"net/http"
	"net/url"

	"agentchaos/api"
	"agentchaos/control"
	"agentchaos/evidence"
	"agentchaos/governor"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	broker := flag.String("broker", "http://127.0.0.1:8081",
		"upstream effect broker URL")
	compilerDir := flag.String("compiler-dir", "../control-plane",
		"directory containing the acx_compiler Python package")
	flag.Parse()

	brokerURL, err := url.Parse(*broker)
	if err != nil {
		log.Fatalf("broker URL: %v", err)
	}

	server := api.New(
		governor.New(nil),
		&evidence.Server{Recorder: evidence.New()},
		control.NewAssurer(),
		api.NewPythonCompiler(*compilerDir),
		brokerURL,
	)
	log.Printf("apid listening on %s (broker %s)", *addr, brokerURL)
	log.Fatal(http.ListenAndServe(*addr, server.Handler()))
}
