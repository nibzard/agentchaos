package broker

import _ "embed"

// DefaultPolicyJSON is the fixture-mode default policy: brokered
// reads, synthetic sink publishes, and costed repository comments.
// Deployments override it with their own versioned document.
//
//go:embed policy.json
var DefaultPolicyJSON []byte
