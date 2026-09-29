package render

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWrap(t *testing.T) {
	s := "the quick brown fox jumps over the lazy dog and keeps running far away"
	lines := wrap(s, 20)
	if strings.Join(lines, " ") != s {
		t.Fatalf("wrap lost words: %q", lines)
	}
	for _, l := range lines {
		if utf8.RuneCountInString(l) > 20 {
			t.Errorf("line too long (%d): %q", len(l), l)
		}
	}
	if wrap("", 10) != nil {
		t.Error("wrap of empty string should be nil")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("got %q", got)
	}
	if got := truncate("a much longer string", 10); utf8.RuneCountInString(got) != 10 || !strings.HasSuffix(got, "…") {
		t.Errorf("got %q", got)
	}
}

func TestTechniqueURL(t *testing.T) {
	cases := map[string]string{
		"T1059":     "https://attack.mitre.org/techniques/T1059/",
		"T1003.001": "https://attack.mitre.org/techniques/T1003/001/",
	}
	for in, want := range cases {
		if got := TechniqueURL(in); got != want {
			t.Errorf("TechniqueURL(%s) = %s, want %s", in, got, want)
		}
	}
}
