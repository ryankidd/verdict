// Package finding defines the shared finding type that scanning tools emit
// and verdict aggregates.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// Finding is a single issue reported by a scanning tool.
type Finding struct {
	Tool        string `json:"tool"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Message     string `json:"message"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ComputeFingerprint returns a stable identifier for the finding, derived
// from Tool, Rule, Path, and Line. Two findings with the same fingerprint
// are considered the same finding across repeated runs, even if Message
// changed wording. Message is deliberately excluded from the derivation
// so that rewording a message doesn't churn dedupe state.
func ComputeFingerprint(f Finding) string {
	sum := sha256.Sum256([]byte(f.Tool + "\x00" + f.Rule + "\x00" + f.Path + "\x00" + strconv.Itoa(f.Line)))
	return hex.EncodeToString(sum[:])[:16]
}

// Decode reads a JSON array of findings from r. Any finding without a
// fingerprint has one computed and filled in.
func Decode(r io.Reader) ([]Finding, error) {
	var findings []Finding
	if err := json.NewDecoder(r).Decode(&findings); err != nil {
		return nil, fmt.Errorf("decode findings: %w", err)
	}
	for i, f := range findings {
		if f.Fingerprint == "" {
			findings[i].Fingerprint = ComputeFingerprint(f)
		}
	}
	return findings, nil
}
