package finding

// Severity is the ordered seriousness of a finding. Larger values are more
// serious, so two severities can be compared directly with the ordinary
// comparison operators.
type Severity int

// The severity levels, from least to most serious. The order is what makes
// threshold gating possible: a caller can ask whether anything reaches a
// given level by comparing against it.
const (
	Info Severity = iota
	Warning
	Error
)

var severityByName = map[string]Severity{
	"info":    Info,
	"warning": Warning,
	"error":   Error,
}

// ParseSeverity maps a severity string from the envelope to its ordered
// value. It reports whether the string named a known severity; an unknown
// value yields the zero Severity and false.
func ParseSeverity(s string) (Severity, bool) {
	sev, ok := severityByName[s]
	return sev, ok
}
