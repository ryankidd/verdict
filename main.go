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

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "usage: verdict [file...]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Merges the given findings files into a single deduplicated, ordered")
		fmt.Fprintln(out, "JSON array on stdout. Reads stdin when no files are given.")
	}
	flag.Parse()

	if err := run(flag.Args(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "verdict:", err)
		os.Exit(1)
	}
}

func run(paths []string, stdin io.Reader, out io.Writer) error {
	var sets [][]finding.Finding

	if len(paths) == 0 {
		findings, err := finding.Decode(stdin)
		if err != nil {
			return fmt.Errorf("stdin: %w", err)
		}
		sets = append(sets, findings)
	}
	for _, path := range paths {
		findings, err := decodeFile(path)
		if err != nil {
			return err
		}
		sets = append(sets, findings)
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(finding.Merge(sets...))
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
