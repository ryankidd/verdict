package finding

import (
	"slices"
	"testing"
)

func mk(tool, rule, path string, line int) Finding {
	f := Finding{
		Tool:     tool,
		Rule:     rule,
		Severity: "error",
		Path:     path,
		Line:     line,
		Message:  tool + " " + rule,
	}
	f.Fingerprint = ComputeFingerprint(f)
	return f
}

func fingerprints(findings []Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.Fingerprint
	}
	return out
}

func TestMergeCombinesSets(t *testing.T) {
	a := []Finding{mk("secretscan", "aws-key", "config.go", 12)}
	b := []Finding{mk("lint", "unused", "main.go", 3)}

	got := Merge(a, b)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
}

func TestMergeDedupesByFingerprint(t *testing.T) {
	f := mk("secretscan", "aws-key", "config.go", 12)

	got := Merge([]Finding{f}, []Finding{f})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
}

func TestMergeKeepsFirstOccurrenceOfDuplicate(t *testing.T) {
	first := mk("secretscan", "aws-key", "config.go", 12)
	first.Message = "first wording"
	second := first
	second.Message = "second wording"
	second.Severity = "warning"

	got := Merge([]Finding{first}, []Finding{second})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Message != "first wording" {
		t.Errorf("got message %q, want %q", got[0].Message, "first wording")
	}
	if got[0].Severity != "error" {
		t.Errorf("got severity %q, want %q", got[0].Severity, "error")
	}
}

func TestMergeDedupesWithinASingleSet(t *testing.T) {
	f := mk("secretscan", "aws-key", "config.go", 12)

	got := Merge([]Finding{f, f})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

func TestMergeOrdersByPathLineRuleTool(t *testing.T) {
	got := Merge([]Finding{
		mk("lint", "unused", "main.go", 3),
		mk("secretscan", "aws-key", "config.go", 40),
		mk("lint", "shadow", "config.go", 12),
		mk("secretscan", "aws-key", "config.go", 12),
		mk("audit", "aws-key", "config.go", 12),
	})

	type key struct {
		path string
		line int
		rule string
		tool string
	}
	want := []key{
		{"config.go", 12, "aws-key", "audit"},
		{"config.go", 12, "aws-key", "secretscan"},
		{"config.go", 12, "shadow", "lint"},
		{"config.go", 40, "aws-key", "secretscan"},
		{"main.go", 3, "unused", "lint"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := key{got[i].Path, got[i].Line, got[i].Rule, got[i].Tool}
		if g != w {
			t.Errorf("position %d: got %+v, want %+v", i, g, w)
		}
	}
}

func TestMergeOrderIndependentOfSetOrder(t *testing.T) {
	a := []Finding{
		mk("lint", "unused", "main.go", 3),
		mk("secretscan", "aws-key", "config.go", 12),
	}
	b := []Finding{
		mk("lint", "shadow", "config.go", 12),
		mk("secretscan", "aws-key", "config.go", 40),
	}

	forward := fingerprints(Merge(a, b))
	reverse := fingerprints(Merge(b, a))
	if !slices.Equal(forward, reverse) {
		t.Errorf("order depends on set order: %v vs %v", forward, reverse)
	}
}

func TestMergeSeparatesSuppliedFingerprintsSharingASortKey(t *testing.T) {
	a := mk("secretscan", "aws-key", "config.go", 12)
	a.Fingerprint = "aaaa"
	b := a
	b.Fingerprint = "bbbb"

	got := Merge([]Finding{b}, []Finding{a})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if got[0].Fingerprint != "aaaa" || got[1].Fingerprint != "bbbb" {
		t.Errorf("got fingerprints %v, want [aaaa bbbb]", fingerprints(got))
	}
}

func TestMergeFillsMissingFingerprint(t *testing.T) {
	f := mk("secretscan", "aws-key", "config.go", 12)
	bare := f
	bare.Fingerprint = ""

	got := Merge([]Finding{bare})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Fingerprint != f.Fingerprint {
		t.Errorf("got fingerprint %q, want %q", got[0].Fingerprint, f.Fingerprint)
	}
}

func TestMergeWithoutSetsReturnsEmptySlice(t *testing.T) {
	got := Merge()
	if got == nil {
		t.Fatal("Merge returned nil, want empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("got %d findings, want 0", len(got))
	}
}

func TestMergeDoesNotModifyInput(t *testing.T) {
	f := mk("secretscan", "aws-key", "config.go", 12)
	f.Fingerprint = ""
	set := []Finding{f}

	Merge(set)
	if set[0].Fingerprint != "" {
		t.Errorf("Merge modified its input: fingerprint set to %q", set[0].Fingerprint)
	}
}
