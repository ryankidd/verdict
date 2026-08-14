package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryankidd/verdict/internal/finding"
)

func writeFile(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func runOK(t *testing.T, paths []string, stdin string) []finding.Finding {
	t.Helper()
	var out bytes.Buffer
	if _, err := run(paths, "", strings.NewReader(stdin), &out); err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	var findings []finding.Finding
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("output is not a findings array: %v\n%s", err, out.String())
	}
	return findings
}

const (
	setA = `[
	  {"tool":"secretscan","rule":"aws-key","severity":"error","path":"config.go","line":12,"message":"possible AWS access key"},
	  {"tool":"lint","rule":"unused","severity":"warning","path":"main.go","line":3,"message":"unused variable"}
	]`
	setB = `[
	  {"tool":"secretscan","rule":"aws-key","severity":"error","path":"config.go","line":12,"message":"possible AWS access key"},
	  {"tool":"lint","rule":"shadow","severity":"warning","path":"config.go","line":40,"message":"declaration shadows outer"}
	]`
	// setLow carries nothing more serious than a warning, so a threshold of
	// error clears it while a threshold of warning does not.
	setLow = `[
	  {"tool":"lint","rule":"unused","severity":"warning","path":"main.go","line":3,"message":"unused variable"},
	  {"tool":"lint","rule":"style","severity":"info","path":"main.go","line":7,"message":"prefer tabs"}
	]`
)

func TestRunMergesAndDedupesFiles(t *testing.T) {
	a := writeFile(t, "a.json", setA)
	b := writeFile(t, "b.json", setB)

	findings := runOK(t, []string{a, b}, "")
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(findings), findings)
	}

	want := []struct {
		path string
		line int
	}{
		{"config.go", 12},
		{"config.go", 40},
		{"main.go", 3},
	}
	for i, w := range want {
		if findings[i].Path != w.path || findings[i].Line != w.line {
			t.Errorf("position %d: got %s:%d, want %s:%d", i, findings[i].Path, findings[i].Line, w.path, w.line)
		}
	}
}

func TestRunOutputIndependentOfFileOrder(t *testing.T) {
	a := writeFile(t, "a.json", setA)
	b := writeFile(t, "b.json", setB)

	var forward, reverse bytes.Buffer
	if _, err := run([]string{a, b}, "", strings.NewReader(""), &forward); err != nil {
		t.Fatalf("run(a, b) returned error: %v", err)
	}
	if _, err := run([]string{b, a}, "", strings.NewReader(""), &reverse); err != nil {
		t.Fatalf("run(b, a) returned error: %v", err)
	}
	if forward.String() != reverse.String() {
		t.Errorf("output differs with file order:\n%s\n---\n%s", forward.String(), reverse.String())
	}
}

func TestRunReadsStdinWithoutFiles(t *testing.T) {
	findings := runOK(t, nil, setA)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	if findings[0].Path != "config.go" || findings[1].Path != "main.go" {
		t.Errorf("got paths %s, %s; want config.go, main.go", findings[0].Path, findings[1].Path)
	}
}

func TestRunEmitsEmptyArray(t *testing.T) {
	var out bytes.Buffer
	if _, err := run(nil, "", strings.NewReader("[]"), &out); err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "[]" {
		t.Errorf("got %q, want %q", got, "[]")
	}
}

func TestRunReportsMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")

	_, err := run([]string{missing}, "", strings.NewReader(""), &bytes.Buffer{})
	if err == nil {
		t.Fatal("run returned no error for a missing file")
	}
	if !strings.Contains(err.Error(), "nope.json") {
		t.Errorf("error does not name the file: %v", err)
	}
}

func TestRunReportsMalformedFile(t *testing.T) {
	good := writeFile(t, "good.json", setA)
	bad := writeFile(t, "bad.json", `{"not":"an array"}`)

	var out bytes.Buffer
	_, err := run([]string{good, bad}, "", strings.NewReader(""), &out)
	if err == nil {
		t.Fatal("run returned no error for a malformed file")
	}
	if !strings.Contains(err.Error(), "bad.json") {
		t.Errorf("error does not name the file: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("run wrote output despite the error: %s", out.String())
	}
}

func TestRunFailOnMeetsThreshold(t *testing.T) {
	var out bytes.Buffer
	met, err := run(nil, "error", strings.NewReader(setA), &out)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !met {
		t.Error("run did not report the error-severity finding meeting -fail-on error")
	}

	// The merge is still printed; gating never suppresses output.
	var findings []finding.Finding
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatalf("output is not a findings array: %v\n%s", err, out.String())
	}
	if len(findings) != 2 {
		t.Errorf("got %d findings, want 2", len(findings))
	}
}

func TestRunFailOnBelowThreshold(t *testing.T) {
	var out bytes.Buffer
	met, err := run(nil, "error", strings.NewReader(setLow), &out)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if met {
		t.Error("run reported meeting -fail-on error with only warning and info findings")
	}
	if out.Len() == 0 {
		t.Error("run wrote no output below the threshold")
	}
}

func TestRunFailOnAtThreshold(t *testing.T) {
	var out bytes.Buffer
	met, err := run(nil, "warning", strings.NewReader(setLow), &out)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !met {
		t.Error("run did not report the warning finding meeting -fail-on warning")
	}
}

func TestRunFailOnUnsetNeverMeets(t *testing.T) {
	var out bytes.Buffer
	met, err := run(nil, "", strings.NewReader(setA), &out)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if met {
		t.Error("run reported meeting a threshold without -fail-on set")
	}
}

func TestRunFailOnInvalidValue(t *testing.T) {
	var out bytes.Buffer
	met, err := run(nil, "critical", strings.NewReader(setA), &out)
	if err == nil {
		t.Fatal("run returned no error for an invalid -fail-on value")
	}
	if !strings.Contains(err.Error(), "critical") {
		t.Errorf("error does not name the bad value: %v", err)
	}
	if met {
		t.Error("run reported meeting a threshold on an invalid -fail-on value")
	}
	if out.Len() != 0 {
		t.Errorf("run wrote output despite the invalid value: %s", out.String())
	}
}
