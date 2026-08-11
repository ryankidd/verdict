package finding

import (
	"cmp"
	"slices"
)

// Merge combines several sets of findings into one deduplicated, ordered set.
//
// Two findings are duplicates when they share a fingerprint. Where duplicates
// disagree on fields outside the fingerprint derivation — severity and message —
// the first occurrence wins, scanning the sets in the order given and each set
// front to back. The fingerprint is the identity of a finding, so the losing
// copy is a different rendering of the same issue rather than a separate one;
// keeping the first makes the earlier input authoritative.
//
// The result is sorted by path, line, rule, tool, then fingerprint. That key is
// total across findings that survive deduplication, so the output does not
// depend on the order the sets were given. The fingerprint is part of the key
// because a tool may supply its own, in which case two findings can agree on
// tool, rule, path, and line yet remain distinct.
//
// Findings without a fingerprint have one computed before comparison. The
// returned slice is never nil.
func Merge(sets ...[]Finding) []Finding {
	merged := make([]Finding, 0)
	seen := make(map[string]struct{})

	for _, set := range sets {
		for _, f := range set {
			if f.Fingerprint == "" {
				f.Fingerprint = ComputeFingerprint(f)
			}
			if _, dup := seen[f.Fingerprint]; dup {
				continue
			}
			seen[f.Fingerprint] = struct{}{}
			merged = append(merged, f)
		}
	}

	slices.SortFunc(merged, compare)
	return merged
}

// compare orders two findings by the total sort key described on Merge.
func compare(a, b Finding) int {
	if c := cmp.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Line, b.Line); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Rule, b.Rule); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Tool, b.Tool); c != 0 {
		return c
	}
	return cmp.Compare(a.Fingerprint, b.Fingerprint)
}
