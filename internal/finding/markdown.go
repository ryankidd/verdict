package finding

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Markdown renders findings as a human-readable report grouped by tool, then
// by file within each tool. Each finding is listed with its location as
// path:line, its rule, its severity, and its message.
//
// Tools and the files under them are emitted in ascending name order, and the
// findings within a file are ordered by the same total key Merge uses, so the
// report is deterministic whatever order the findings arrive in. An empty set
// renders a report with no groups.
func Markdown(findings []Finding) string {
	var b strings.Builder
	b.WriteString("# Findings\n")

	if len(findings) == 0 {
		b.WriteString("\nNo findings.\n")
		return b.String()
	}

	// Group by tool, then by file.
	byTool := make(map[string]map[string][]Finding)
	for _, f := range findings {
		byFile := byTool[f.Tool]
		if byFile == nil {
			byFile = make(map[string][]Finding)
			byTool[f.Tool] = byFile
		}
		byFile[f.Path] = append(byFile[f.Path], f)
	}

	for _, tool := range sortedKeys(byTool) {
		fmt.Fprintf(&b, "\n## %s\n", tool)

		byFile := byTool[tool]
		for _, path := range sortedKeys(byFile) {
			fmt.Fprintf(&b, "\n### %s\n\n", path)

			group := byFile[path]
			slices.SortFunc(group, compare)
			for _, f := range group {
				fmt.Fprintf(&b, "- %s:%d — `%s` (%s): %s\n", f.Path, f.Line, f.Rule, f.Severity, f.Message)
			}
		}
	}

	return b.String()
}

// sortedKeys returns the keys of m in ascending order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, cmp.Compare)
	return keys
}
