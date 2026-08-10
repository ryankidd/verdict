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
		Tool:     "secretscan",
		Rule:     "aws-key",
		Severity: "error",
		Path:     "config.go",
		Line:     12,
		Message:  "possible AWS access key",
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
