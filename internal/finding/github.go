package finding

import (
	"fmt"
	"slices"
	"strings"
)

// GitHub renders findings as GitHub Actions workflow commands, one per line.
// When such a line is printed on a runner, GitHub turns it into an annotation
// attached to the file and line it names.
//
// Each finding becomes a line of the form
//
//	::<level> file=<path>,line=<line>,title=<rule>::<message>
//
// where <level> maps the finding's severity: error to error, warning to
// warning, and info to notice, the three levels GitHub understands. A severity
// outside those three is annotated as a notice so it is surfaced without being
// escalated.
//
// The file, line, and title properties are omitted when the finding has no
// path, no line, or no rule respectively, since an empty property value is not
// meaningful. Values are escaped following GitHub's workflow-command rules.
//
// Findings are emitted in the same total order Merge produces, so the output
// is deterministic whatever order they arrive in. An empty set renders as the
// empty string.
func GitHub(findings []Finding) string {
	ordered := slices.Clone(findings)
	slices.SortFunc(ordered, compare)

	var b strings.Builder
	for _, f := range ordered {
		b.WriteString("::")
		b.WriteString(annotationLevel(f.Severity))

		var props []string
		if f.Path != "" {
			props = append(props, "file="+escapeProperty(f.Path))
		}
		if f.Line != 0 {
			props = append(props, fmt.Sprintf("line=%d", f.Line))
		}
		if f.Rule != "" {
			props = append(props, "title="+escapeProperty(f.Rule))
		}
		if len(props) > 0 {
			b.WriteString(" ")
			b.WriteString(strings.Join(props, ","))
		}

		b.WriteString("::")
		b.WriteString(escapeData(f.Message))
		b.WriteString("\n")
	}

	return b.String()
}

// annotationLevel maps a finding's severity to a GitHub annotation level. The
// three known severities map to error, warning, and notice; anything else is
// surfaced as a notice.
func annotationLevel(severity string) string {
	switch severity {
	case "error":
		return "error"
	case "warning":
		return "warning"
	default:
		return "notice"
	}
}

// escapeData escapes the message portion of a workflow command. Both replacers
// run in a single left-to-right pass, so the % inserted by an escape is never
// itself re-escaped.
var dataEscaper = strings.NewReplacer(
	"%", "%25",
	"\r", "%0D",
	"\n", "%0A",
)

// escapeProperty escapes a property value, which needs the message escapes plus
// the comma and colon that would otherwise end the value or separate it from
// the next property.
var propertyEscaper = strings.NewReplacer(
	"%", "%25",
	"\r", "%0D",
	"\n", "%0A",
	":", "%3A",
	",", "%2C",
)

func escapeData(s string) string     { return dataEscaper.Replace(s) }
func escapeProperty(s string) string { return propertyEscaper.Replace(s) }
