// Command governord serves the independent safety governor and ticks
// the sweep that trips expired grants (spec 13.2, AC-006).
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gauntlet/governor"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8082", "listen address")
	sweepEvery := flag.Duration("sweep-every", time.Second, "sweep interval")
	flag.Parse()

	daemon := governor.New(time.Now)
	server := &http.Server{
		Addr:              *addr,
		Handler:           (&governor.Server{Governor: daemon}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ticker := time.NewTicker(*sweepEvery)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			daemon.Sweep()
		}
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("governord listening on %s", *addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
