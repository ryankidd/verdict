// Package finding defines the shared finding type that scanning tools emit
// and verdict aggregates.
package finding

import (
	"encoding/json"
	"fmt"
	"io"
)

// Finding is a single issue reported by a scanning tool.
type Finding struct {
	Tool     string `json:"tool"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// Decode reads a JSON array of findings from r.
func Decode(r io.Reader) ([]Finding, error) {
	var findings []Finding
	if err := json.NewDecoder(r).Decode(&findings); err != nil {
		return nil, fmt.Errorf("decode findings: %w", err)
	}
	return findings, nil
}
