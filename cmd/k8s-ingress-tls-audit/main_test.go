package main

import (
	"testing"
	"time"
)

func TestParseNow(t *testing.T) {
	clock, err := parseNow("")
	if err != nil || clock != nil {
		t.Fatalf(`parseNow("") = %v, %v; want nil clock, nil error`, clock, err)
	}

	clock, err = parseNow("2026-09-15T00:00:00Z")
	if err != nil {
		t.Fatalf("parseNow: %v", err)
	}
	want := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	if got := clock(); !got.Equal(want) {
		t.Errorf("clock() = %v, want %v", got, want)
	}

	for _, bad := range []string{"2026-09-15", "yesterday", "2026-09-15 00:00:00"} {
		if _, err := parseNow(bad); err == nil {
			t.Errorf("parseNow(%q): expected an error", bad)
		}
	}
}
