// Command verdict merges JSON findings files into one deduplicated,
// deterministically ordered array.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ryankidd/verdict/internal/finding"
)

// Exit codes. A clean run is exitOK. When -fail-on is set and a finding
// reaches the threshold the merge still prints, but the process exits with
// exitThreshold so CI can gate on it. Any usage or input error exits with
// exitError, kept distinct so "the tool broke" reads differently from "the
// tool ran and found something worth failing on".
const (
	exitOK        = 0
	exitError     = 1
	exitThreshold = 2
)

func main() {
	failOn := flag.String("fail-on", "", "exit with status 2 if any finding's severity is at or above this level (error, warning, or info)")
	format := flag.String("format", "json", "output format: json or markdown")
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "usage: verdict [-fail-on severity] [-format json|markdown] [file...]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Merges the given findings files into a single deduplicated, ordered")
		fmt.Fprintln(out, "set and writes it to stdout. Reads stdin when no files are given.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "With -format markdown, writes a human-readable report grouped by tool")
		fmt.Fprintln(out, "and then by file instead of the default JSON array.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "With -fail-on, exits with status 2 if any finding's severity is at or")
		fmt.Fprintln(out, "above the given level (error, warning, or info).")
	}
	flag.Parse()

	met, err := run(flag.Args(), *failOn, *format, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verdict:", err)
		os.Exit(exitError)
	}
	if met {
		os.Exit(exitThreshold)
	}
	os.Exit(exitOK)
}

// run merges the findings from paths (or stdin when paths is empty) onto out.
// The format selects the rendering: "json" writes the deduplicated, ordered
// array; "markdown" writes a report grouped by tool and then by file. When
// failOn names a severity, run reports whether any merged finding sits at or
// above it; the report is meaningful only when the returned error is nil.
func run(paths []string, failOn, format string, stdin io.Reader, out io.Writer) (bool, error) {
	switch format {
	case "json", "markdown":
	default:
		return false, fmt.Errorf("invalid -format value %q: want json or markdown", format)
	}

	var threshold finding.Severity
	if failOn != "" {
		var ok bool
		threshold, ok = finding.ParseSeverity(failOn)
		if !ok {
			return false, fmt.Errorf("invalid -fail-on value %q: want error, warning, or info", failOn)
		}
	}

	var sets [][]finding.Finding

	if len(paths) == 0 {
		findings, err := finding.Decode(stdin)
		if err != nil {
			return false, fmt.Errorf("stdin: %w", err)
		}
		sets = append(sets, findings)
	}
	for _, path := range paths {
		findings, err := decodeFile(path)
		if err != nil {
			return false, err
		}
		sets = append(sets, findings)
	}

	merged := finding.Merge(sets...)

	if format == "markdown" {
		if _, err := io.WriteString(out, finding.Markdown(merged)); err != nil {
			return false, err
		}
	} else {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(merged); err != nil {
			return false, err
		}
	}

	if failOn == "" {
		return false, nil
	}
	return meetsThreshold(merged, threshold), nil
}

// meetsThreshold reports whether any finding's severity is at or above the
// threshold. Findings whose severity is not one of the known levels are
// ignored: they cannot be placed in the ordering, so they never trip a gate.
func meetsThreshold(findings []finding.Finding, threshold finding.Severity) bool {
	for _, f := range findings {
		if sev, ok := finding.ParseSeverity(f.Severity); ok && sev >= threshold {
			return true
		}
	}
	return false
}

func decodeFile(path string) ([]finding.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	findings, err := finding.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return findings, nil
}
