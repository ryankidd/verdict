package finding

import "testing"

func TestParseSeverityKnownValues(t *testing.T) {
	for _, name := range []string{"info", "warning", "error"} {
		if _, ok := ParseSeverity(name); !ok {
			t.Errorf("ParseSeverity(%q) reported unknown, want known", name)
		}
	}
}

func TestParseSeverityUnknownValue(t *testing.T) {
	if sev, ok := ParseSeverity("critical"); ok || sev != Info {
		t.Errorf("ParseSeverity(%q) = %v, %v; want %v, false", "critical", sev, ok, Info)
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !(Error > Warning && Warning > Info) {
		t.Errorf("severity order is not error > warning > info: error=%d warning=%d info=%d", Error, Warning, Info)
	}
}

func TestParseSeverityRoundTripsOrder(t *testing.T) {
	info, _ := ParseSeverity("info")
	warning, _ := ParseSeverity("warning")
	err, _ := ParseSeverity("error")
	if !(err > warning && warning > info) {
		t.Errorf("parsed severities do not preserve order: info=%d warning=%d error=%d", info, warning, err)
	}
}
