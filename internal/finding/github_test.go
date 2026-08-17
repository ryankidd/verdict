package finding

import (
	"strings"
	"testing"
)

func TestGitHubRendersOneAnnotationPerFinding(t *testing.T) {
	got := GitHub([]Finding{
		mk("lint", "unused", "main.go", 3),
		mk("secretscan", "aws-key", "config.go", 12),
	})

	// Ordered by the same key Merge uses: config.go before main.go.
	want := strings.Join([]string{
		"::error file=config.go,line=12,title=aws-key::secretscan aws-key",
		"::error file=main.go,line=3,title=unused::lint unused",
		"",
	}, "\n")

	if got != want {
		t.Errorf("annotation mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestGitHubMapsSeverityToLevel(t *testing.T) {
	cases := []struct {
		severity string
		level    string
	}{
		{"error", "error"},
		{"warning", "warning"},
		{"info", "notice"},
		{"critical", "notice"}, // unknown severities fall back to notice
	}
	for _, c := range cases {
		f := mk("lint", "rule", "main.go", 1)
		f.Severity = c.severity
		got := GitHub([]Finding{f})
		want := "::" + c.level + " "
		if !strings.HasPrefix(got, want) {
			t.Errorf("severity %q: got %q, want prefix %q", c.severity, got, want)
		}
	}
}

func TestGitHubOmitsLineWhenAbsent(t *testing.T) {
	f := mk("lint", "unused", "main.go", 0)
	got := GitHub([]Finding{f})

	if strings.Contains(got, "line=") {
		t.Errorf("expected no line property when line is absent:\n%s", got)
	}
	if !strings.Contains(got, "file=main.go") {
		t.Errorf("expected file property to remain:\n%s", got)
	}
	if !strings.Contains(got, "title=unused") {
		t.Errorf("expected title property to remain:\n%s", got)
	}
}

func TestGitHubOmitsFileWhenAbsent(t *testing.T) {
	f := mk("lint", "unused", "", 4)
	got := GitHub([]Finding{f})

	if strings.Contains(got, "file=") {
		t.Errorf("expected no file property when path is absent:\n%s", got)
	}
	if !strings.Contains(got, "line=4") {
		t.Errorf("expected line property to remain:\n%s", got)
	}
}

func TestGitHubOmitsAllPropertiesWhenAbsent(t *testing.T) {
	f := Finding{Severity: "info", Message: "no location"}
	got := GitHub([]Finding{f})

	want := "::notice::no location\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGitHubEscapesMessage(t *testing.T) {
	f := mk("lint", "rule", "main.go", 1)
	f.Message = "100% done\r\nnext line"
	got := GitHub([]Finding{f})

	if !strings.HasSuffix(got, "::100%25 done%0D%0Anext line\n") {
		t.Errorf("message not escaped per data rules:\n%s", got)
	}
	// Commas and colons are not escaped in message data.
	f.Message = "a, b: c"
	got = GitHub([]Finding{f})
	if !strings.HasSuffix(got, "::a, b: c\n") {
		t.Errorf("message data should not escape comma or colon:\n%s", got)
	}
}

func TestGitHubEscapesPropertyValues(t *testing.T) {
	f := Finding{
		Severity: "error",
		Path:     "a,b:c/main.go",
		Line:     2,
		Rule:     "x:y,z%",
		Message:  "m",
	}
	got := GitHub([]Finding{f})

	want := "::error file=a%2Cb%3Ac/main.go,line=2,title=x%3Ay%2Cz%25::m\n"
	if got != want {
		t.Errorf("property escaping mismatch:\ngot  %q\nwant %q", got, want)
	}
}

func TestGitHubEscapesPercentBeforeOtherSequences(t *testing.T) {
	// A literal "%0A" in the input must not be confused with an escaped
	// newline: the percent is escaped first, yielding "%250A".
	f := mk("lint", "rule", "main.go", 1)
	f.Message = "%0A"
	got := GitHub([]Finding{f})

	if !strings.HasSuffix(got, "::%250A\n") {
		t.Errorf("literal %%0A should escape to %%250A, not stay %%0A:\n%s", got)
	}
}

func TestGitHubEmptyRendersNothing(t *testing.T) {
	if got := GitHub(nil); got != "" {
		t.Errorf("empty set should render nothing, got %q", got)
	}
}
