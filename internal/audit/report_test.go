package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteTable_Empty(t *testing.T) {
	var b bytes.Buffer
	if err := WriteTable(&b, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "OK: no TLS problems") {
		t.Errorf("empty table = %q", b.String())
	}
}

func TestWriteTable_Findings(t *testing.T) {
	var b bytes.Buffer
	fs := []Finding{{Namespace: "prod", Ingress: "web", Host: "a.example.com",
		Severity: SeverityMissingTLS, Kind: "missing_tls", Message: "no tls"}}
	if err := WriteTable(&b, fs); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"SEVERITY", "missing_tls", "prod", "web", "a.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q in:\n%s", want, out)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	var b bytes.Buffer
	fs := []Finding{{Namespace: "prod", Ingress: "web", Secret: "gone",
		Severity: SeverityMissingSecret, Kind: "missing_secret", Message: "absent"}}
	if err := WriteJSON(&b, fs); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got[0]["severity"] != "missing_secret" {
		t.Errorf("severity = %v, want missing_secret", got[0]["severity"])
	}
	if got[0]["kind"] != "missing_secret" {
		t.Errorf("kind = %v", got[0]["kind"])
	}
}
