// Command evid serves the evidence plane's HTTP interface.
package main

import (
	"flag"
	"log"
	"net/http"

	"agentchaos/evidence"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8082", "listen address")
	flag.Parse()

	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}

	recorder := evidence.New()
	server := &evidence.Server{Recorder: recorder}

	log.Printf("evid listening on %s (checkpoints signed by %s)",
		*addr, recorder.SigningKeyID())
	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		log.Fatal(err)
	}
}
