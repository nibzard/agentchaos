package analysis

// Tests for the portable report export (spec 17.5, AC-025, T030):
// the title and metadata carry the synthetic/production distinction,
// artifacts are named by digest, evidence is referenced, the gate
// never infers a pass from absence, and both renders come from one
// document.

import (
	"encoding/json"
	"strings"
	"testing"
)

func reportFixture() ReportInput {
	return ReportInput{
		Environment:       EnvironmentSynthetic,
		TenantID:          "tnt_demo000000000001",
		GeneratedAt:       "2026-09-12T00:00:00Z",
		WorkloadVersionID: "wlv_0a1b2c3d4e5f6071",
		AutonomyProfiles:  []string{"profile-full", "profile-baseline"},
		ExperimentID:      "exp_0a1b2c3d4e5f6071",
		Runs: []RunGateInput{
			{RunID: "run_baseline00001", State: "stopped", Terminal: "CLEAN"},
			{RunID: "run_treatment001", State: "stopped", Terminal: "CLEAN"},
		},
		Outcomes: ReportOutcomes{Passed: 12, Failed: 1, Unknown: 2},
		Artifacts: []ReportArtifact{
			{Name: "plan.json", Digest: DigestBytes([]byte("plan")),
				Bytes: 4, ContentType: "application/json"},
			{Name: "events.jsonl", Digest: DigestBytes([]byte("events")),
				Bytes: 6},
		},
		Evidence: ReportEvidence{
			ChainHead: DigestBytes([]byte("chain head")),
			Events:    348,
			Claims: []string{
				"clm_0123456789abcdef", "clm_ffffffffffffffff",
			},
		},
	}
}

func TestExportCarriesTheEnvironmentDistinction(t *testing.T) {
	report, err := ExportReport(reportFixture())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.Title, "synthetic") {
		t.Fatalf("title without distinction: %q", report.Title)
	}
	if report.Environment != EnvironmentSynthetic {
		t.Fatalf("environment: %q", report.Environment)
	}

	production := reportFixture()
	production.Environment = EnvironmentProduction
	report, err = ExportReport(production)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.Title, "production") {
		t.Fatalf("production title: %q", report.Title)
	}
	if report.Environment != EnvironmentProduction {
		t.Fatalf("production metadata: %q", report.Environment)
	}
}

func TestExportNamesArtifactsByDigest(t *testing.T) {
	report, err := ExportReport(reportFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Artifacts) != 2 {
		t.Fatalf("artifacts: %v", report.Artifacts)
	}
	// Artifacts sort by name so two exports of one input are
	// byte-identical.
	if report.Artifacts[0].Name != "events.jsonl" ||
		report.Artifacts[1].Name != "plan.json" {
		t.Fatalf("artifact order: %v", report.Artifacts)
	}
	for _, artifact := range report.Artifacts {
		if !strings.HasPrefix(artifact.Digest, "sha256:") {
			t.Fatalf("digest: %v", artifact)
		}
	}
}

func TestExportRefusesHalfAStory(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ReportInput)
	}{
		{"unknown environment", func(in *ReportInput) {
			in.Environment = "staging"
		}},
		{"empty environment", func(in *ReportInput) { in.Environment = "" }},
		{"missing workload version", func(in *ReportInput) {
			in.WorkloadVersionID = ""
		}},
		{"workload version not hex", func(in *ReportInput) {
			in.WorkloadVersionID = "wlv_not-hex-at-all!!"
		}},
		{"missing generated_at", func(in *ReportInput) {
			in.GeneratedAt = ""
		}},
		{"generated_at not a timestamp", func(in *ReportInput) {
			in.GeneratedAt = "sometime"
		}},
		{"zero runs", func(in *ReportInput) { in.Runs = nil }},
		{"run without id", func(in *ReportInput) {
			in.Runs = []RunGateInput{{State: "stopped"}}
		}},
		{"artifact without a name", func(in *ReportInput) {
			in.Artifacts = []ReportArtifact{{Digest: DigestBytes([]byte("x"))}}
		}},
		{"artifact without a digest", func(in *ReportInput) {
			in.Artifacts = []ReportArtifact{{Name: "plan.json"}}
		}},
		{"artifact with a fake digest", func(in *ReportInput) {
			in.Artifacts = []ReportArtifact{
				{Name: "plan.json", Digest: "sha256:abc"}}
		}},
		{"artifact with negative size", func(in *ReportInput) {
			in.Artifacts = []ReportArtifact{
				{Name: "plan.json", Digest: DigestBytes([]byte("x")),
					Bytes: -1}}
		}},
		{"artifact listed twice", func(in *ReportInput) {
			digest := DigestBytes([]byte("x"))
			in.Artifacts = []ReportArtifact{
				{Name: "plan.json", Digest: digest},
				{Name: "plan.json", Digest: digest}}
		}},
		{"claim reference not a claim id", func(in *ReportInput) {
			in.Evidence.Claims = []string{"claim-one"}
		}},
		{"chain head not a digest", func(in *ReportInput) {
			in.Evidence.ChainHead = "head-of-the-chain"
		}},
	}
	for _, testCase := range cases {
		input := reportFixture()
		testCase.mutate(&input)
		if report, err := ExportReport(input); err == nil {
			t.Fatalf("%s: exported %+v", testCase.name, report)
		}
	}
}

func TestRunGatesNeverInferAPassFromAbsence(t *testing.T) {
	cases := []struct {
		state, terminal string
		want            string
	}{
		{"stopped", "CLEAN", GatePassed},
		{"stopped", "DIRTY_QUARANTINED", GateFailed},
		{"fenced", "", GateFailed},
		{"stopped", "UNKNOWN", GateInconclusive},
		{"stopped", "", GateInconclusive},
		{"active", "", GateInconclusive},
	}
	for _, testCase := range cases {
		input := reportFixture()
		input.Runs = []RunGateInput{{
			RunID: "run_gate00000000001", State: testCase.state,
			Terminal: testCase.terminal,
		}}
		report, err := ExportReport(input)
		if err != nil {
			t.Fatal(err)
		}
		run := report.Subject.Runs[0]
		if run.Gate != testCase.want {
			t.Fatalf("state %s terminal %q: gate %s (want %s)",
				testCase.state, testCase.terminal, run.Gate, testCase.want)
		}
		if run.Note == "" {
			t.Fatalf("gate without a note: %+v", run)
		}
	}
}

func TestTheReportGateRollsUpTheRuns(t *testing.T) {
	input := reportFixture()
	input.Runs = []RunGateInput{
		{RunID: "run_a00000000000001", State: "stopped", Terminal: "CLEAN"},
		{RunID: "run_b00000000000001", State: "stopped",
			Terminal: "DIRTY_QUARANTINED"},
	}
	report, err := ExportReport(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Gate.Status != GateFailed ||
		!strings.Contains(report.Gate.Basis, "1 of 2") {
		t.Fatalf("roll-up: %+v", report.Gate)
	}

	// A clean pair passes.
	report, err = ExportReport(reportFixture())
	if err != nil {
		t.Fatal(err)
	}
	if report.Gate.Status != GatePassed {
		t.Fatalf("clean pair gate: %+v", report.Gate)
	}

	// An active run keeps the report inconclusive even beside a
	// clean one.
	input = reportFixture()
	input.Runs = []RunGateInput{
		{RunID: "run_a00000000000001", State: "stopped", Terminal: "CLEAN"},
		{RunID: "run_b00000000000001", State: "active"},
	}
	report, err = ExportReport(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Gate.Status != GateInconclusive {
		t.Fatalf("active roll-up: %+v", report.Gate)
	}
}

func TestBothRendersComeFromOneDocument(t *testing.T) {
	report, err := ExportReport(reportFixture())
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := RenderJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	reparsed := PortableReport{}
	if err := json.Unmarshal(encoded, &reparsed); err != nil {
		t.Fatalf("machine export does not reparse: %v\n%s", err, encoded)
	}
	if reparsed.Kind != ReportKind || reparsed.APIVersion != "v1" {
		t.Fatalf("machine export identity: %+v", reparsed)
	}
	if reparsed.Subject.WorkloadVersionID != report.Subject.WorkloadVersionID {
		t.Fatalf("machine export subject: %+v", reparsed.Subject)
	}
	if len(reparsed.Evidence.Claims) != 2 {
		t.Fatalf("machine export claims: %+v", reparsed.Evidence)
	}

	text := RenderText(report)
	for _, want := range []string{
		report.Title, "synthetic", "wlv_0a1b2c3d4e5f6071",
		"gate passed", "run_baseline00001", "outcomes 12 passed, 1 failed",
		"348 events", "clm_0123456789abcdef", "events.jsonl",
		"universal safety",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("readable export missing %q:\n%s", want, text)
		}
	}
}

func TestExportIsDeterministic(t *testing.T) {
	first, err := ExportReport(reportFixture())
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := RenderJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	// Shuffle the input orderings: sorted output must not care.
	input := reportFixture()
	input.Artifacts = []ReportArtifact{
		{Name: "events.jsonl", Digest: DigestBytes([]byte("events")),
			Bytes: 6},
		{Name: "plan.json", Digest: DigestBytes([]byte("plan")),
			Bytes: 4, ContentType: "application/json"},
	}
	input.Evidence.Claims = []string{
		"clm_ffffffffffffffff", "clm_0123456789abcdef",
	}
	second, err := ExportReport(input)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := RenderJSON(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("exports differ:\n%s\n%s", firstJSON, secondJSON)
	}
}

func TestEmbeddedAnalysesCarryTheirLimitations(t *testing.T) {
	input := reportFixture()
	input.Comparison = &Comparison{
		Kind: "ProfileComparison", APIVersion: "v1",
		Baseline: BaselineProfile, Model: "m1", Tasks: 3,
		Profiles: []ProfileMetrics{}, Pairs: []PairedDiff{},
		Limitations: []string{"comparison limitation one"},
	}
	input.Cost = &CostReport{
		Kind: "CostReport", APIVersion: "v1", Baseline: BaselineProfile,
		GrandTotalMicros: 1, Limitations: []string{"cost limitation one"},
	}
	report, err := ExportReport(input)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(report.Limitations, "\n")
	for _, want := range []string{"comparison limitation one",
		"cost limitation one", "universal safety"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("limitations: %v", report.Limitations)
		}
	}
	if !strings.Contains(RenderText(report), "limitation") {
		t.Fatalf("readable export hides limitations")
	}
}

func TestDigestBytesIsTheCanonicalDigest(t *testing.T) {
	// sha256("acx"), precomputed so the test pins the exact digest.
	const want = "sha256:" +
		"f77b4f6064c225774a487ff030fff897913a2e858901d35866e79a865f3df697"
	if digest := DigestBytes([]byte("acx")); digest != want {
		t.Fatalf("digest: %s", digest)
	}
	if !reDigest.MatchString(want) {
		t.Fatalf("digest shape: %s", want)
	}
}
