package finding

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// The schema in schema/finding.schema.json is published as a stable
// contract, so a field added to Finding without a matching schema change
// (or the reverse) is a bug rather than a documentation lapse.
func TestFindingMatchesPublishedSchema(t *testing.T) {
	path := filepath.Join("..", "..", "schema", "finding.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	var declared []string
	for name := range schema.Properties {
		declared = append(declared, name)
	}
	sort.Strings(declared)

	if got, want := declared, jsonFieldNames(Finding{}); !reflect.DeepEqual(got, want) {
		t.Errorf("schema properties = %v, Finding JSON fields = %v", got, want)
	}

	// Everything except fingerprint is required: a tool that can't name the
	// rule it fired hasn't reported a usable finding, whereas fingerprints
	// are filled in on decode when a tool leaves them out.
	optional := map[string]bool{"fingerprint": true}
	var wantRequired []string
	for _, name := range declared {
		if !optional[name] {
			wantRequired = append(wantRequired, name)
		}
	}
	got := append([]string(nil), schema.Required...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, wantRequired) {
		t.Errorf("schema required = %v, want %v", got, wantRequired)
	}
}

func jsonFieldNames(v any) []string {
	t := reflect.TypeOf(v)
	names := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		for j := 0; j < len(tag); j++ {
			if tag[j] == ',' {
				tag = tag[:j]
				break
			}
		}
		if tag != "" && tag != "-" {
			names = append(names, tag)
		}
	}
	sort.Strings(names)
	return names
}
