// Command verdict reads a JSON array of findings and pretty-prints them.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ryankidd/verdict/internal/finding"
)

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(in *os.File, out *os.File) error {
	findings, err := finding.Decode(in)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}
