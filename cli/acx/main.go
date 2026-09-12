// Command acx is the AgentChaos operator CLI entry point (spec 17.7).
// All behavior lives in gauntlet/cli/app so tests can drive it with
// stub servers; this file only converts the exit code into a process
// exit status.
package main

import (
	"os"

	"gauntlet/cli/app"
)

func main() {
	os.Exit(app.Main(os.Args[1:], os.Stdout, os.Stderr))
}
