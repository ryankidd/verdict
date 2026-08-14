package finding

import (
	"strings"
	"testing"
)

func TestMarkdownGroupsByToolThenFile(t *testing.T) {
	// A deliberately unsorted input so the renderer's own grouping and
	// ordering, not the input order, decides the layout.
	got := Markdown([]Finding{
		mk("lint", "unused", "main.go", 3),
		mk("secretscan", "aws-key", "config.go", 12),
		mk("lint", "shadow", "config.go", 40),
		mk("lint", "style", "config.go", 7),
	})

	want := strings.Join([]string{
		"# Findings",
		"",
		"## lint",
		"",
		"### config.go",
		"",
		"- config.go:7 — `style` (error): lint style",
		"- config.go:40 — `shadow` (error): lint shadow",
		"",
		"### main.go",
		"",
		"- main.go:3 — `unused` (error): lint unused",
		"",
		"## secretscan",
		"",
		"### config.go",
		"",
		"- config.go:12 — `aws-key` (error): secretscan aws-key",
		"",
	}, "\n")

	if got != want {
		t.Errorf("markdown mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestMarkdownOrdersFindingsWithinAFileByLine(t *testing.T) {
	got := Markdown([]Finding{
		mk("lint", "unused", "main.go", 20),
		mk("lint", "shadow", "main.go", 5),
	})

	five := strings.Index(got, "main.go:5")
	twenty := strings.Index(got, "main.go:20")
	if five == -1 || twenty == -1 {
		t.Fatalf("expected both lines to appear:\n%s", got)
	}
	if five > twenty {
		t.Errorf("line 5 should render before line 20:\n%s", got)
	}
}

func TestMarkdownIsDeterministicRegardlessOfInputOrder(t *testing.T) {
	forward := Markdown(Merge([]Finding{
		mk("lint", "unused", "main.go", 3),
		mk("secretscan", "aws-key", "config.go", 12),
	}, []Finding{
		mk("lint", "shadow", "config.go", 40),
	}))
	reverse := Markdown(Merge([]Finding{
		mk("lint", "shadow", "config.go", 40),
	}, []Finding{
		mk("secretscan", "aws-key", "config.go", 12),
		mk("lint", "unused", "main.go", 3),
	}))

	if forward != reverse {
		t.Errorf("markdown depends on input order:\n--- forward ---\n%s\n--- reverse ---\n%s", forward, reverse)
	}
}

func TestMarkdownEmptyReportsNoFindings(t *testing.T) {
	got := Markdown(nil)
	if !strings.Contains(got, "# Findings") {
		t.Errorf("empty report missing heading:\n%s", got)
	}
	if !strings.Contains(got, "No findings.") {
		t.Errorf("empty report should note there are no findings:\n%s", got)
	}
}
