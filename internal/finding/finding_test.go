package finding

import (
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	input := `[{"tool":"secretscan","rule":"aws-key","severity":"error","path":"config.go","line":12,"message":"possible AWS access key"}]`

	findings, err := Decode(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	got := findings[0]
	want := Finding{
		Tool:        "secretscan",
		Rule:        "aws-key",
		Severity:    "error",
		Path:        "config.go",
		Line:        12,
		Message:     "possible AWS access key",
		Fingerprint: ComputeFingerprint(Finding{Tool: "secretscan", Rule: "aws-key", Path: "config.go", Line: 12}),
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestDecodePreservesSuppliedFingerprint(t *testing.T) {
	input := `[{"tool":"secretscan","rule":"aws-key","severity":"error","path":"config.go","line":12,"message":"possible AWS access key","fingerprint":"custom-fp"}]`

	findings, err := Decode(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if got := findings[0].Fingerprint; got != "custom-fp" {
		t.Errorf("got fingerprint %q, want %q", got, "custom-fp")
	}
}

func TestComputeFingerprintStableAcrossMessage(t *testing.T) {
	a := Finding{Tool: "secretscan", Rule: "aws-key", Path: "config.go", Line: 12, Message: "possible AWS access key"}
	b := a
	b.Message = "reworded message"

	if ComputeFingerprint(a) != ComputeFingerprint(b) {
		t.Errorf("fingerprint changed when only Message changed")
	}
}

func TestComputeFingerprintDiffersByLine(t *testing.T) {
	a := Finding{Tool: "secretscan", Rule: "aws-key", Path: "config.go", Line: 12}
	b := a
	b.Line = 13

	if ComputeFingerprint(a) == ComputeFingerprint(b) {
		t.Errorf("fingerprint did not change when Line changed")
	}
}
