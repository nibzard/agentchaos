package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// CompileFailure is one compiler problem: code, message, JSON path
// (spec 9.1). Compilation fails closed; nothing is a warning.
type CompileFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path"`
}

// ValidationResult is what a validation request produces: the plan
// block the Experiment contract allows, plus the digest-covered plan
// document the run route builds its governor envelope from.
type ValidationResult struct {
	Plan         map[string]any `json:"plan"`
	PlanDocument map[string]any `json:"plan_document"`
}

// Compiler compiles an experiment manifest without executing anything
// (spec 18.2). Only the Python compiler can authorize execution, so the
// API calls it rather than re-implementing it.
type Compiler interface {
	Compile(experiment map[string]any, records map[string][]map[string]any,
		now string) (*ValidationResult, []CompileFailure, error)
}

// pythonCompiler shells out to `python3 -m gauntlet_compiler` in the
// control-plane directory. JSON goes in on standard input and comes
// back on standard output: compile failures are results (ok=false,
// exit 0); a nonzero exit is an outage.
type pythonCompiler struct {
	dir    string // directory containing the gauntlet_compiler package
	python string // interpreter binary
}

// NewPythonCompiler builds a compiler running in the given
// control-plane directory.
func NewPythonCompiler(dir string) Compiler {
	return &pythonCompiler{dir: dir, python: "python3"}
}

type compileReply struct {
	OK           bool             `json:"ok"`
	Plan         map[string]any   `json:"plan"`
	PlanDocument map[string]any   `json:"plan_document"`
	Errors       []CompileFailure `json:"errors"`
}

// Compile runs the subprocess entry. The error return is reserved for
// infrastructure failures (interpreter missing, crash); compile
// refusals come back as failures.
func (p *pythonCompiler) Compile(experiment map[string]any,
	records map[string][]map[string]any, now string) (
	*ValidationResult, []CompileFailure, error) {
	request := map[string]any{
		"experiment": experiment,
		"records":    records,
		"now":        now,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, nil, fmt.Errorf("compile request encoding: %w", err)
	}
	run := exec.Command(p.python, "-m", "gauntlet_compiler")
	run.Dir = p.dir
	run.Stdin = bytes.NewReader(encoded)
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil && stdout.Len() == 0 {
		return nil, nil, fmt.Errorf("compiler run failed: %v: %s",
			err, strings.TrimSpace(stderr.String()))
	}
	var reply compileReply
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		return nil, nil, fmt.Errorf("compiler reply unreadable: %w", err)
	}
	if !reply.OK {
		return nil, reply.Errors, nil
	}
	if reply.Plan == nil || reply.PlanDocument == nil {
		return nil, nil, fmt.Errorf("compiler reply missing plan or plan_document")
	}
	return &ValidationResult{Plan: reply.Plan, PlanDocument: reply.PlanDocument}, nil, nil
}
