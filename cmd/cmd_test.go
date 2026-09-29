package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/MrWaifu24/weix/internal/events"
)

func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	db, loadErr := events.Default()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	root := NewRootCmd(db, "test")
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errOut.String(), err
}

func TestExplain(t *testing.T) {
	out, _, err := run(t, "4625")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"4625  An account failed to log on",
		"Security",
		"T1110.003",
		"Brute Force: Password Spraying",
		"WHY IT MATTERS",
		"KEY FIELDS",
		"INVESTIGATION",
		"COMMON FALSE POSITIVES",
		"RELATED",
		"4740",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("non-TTY output must not contain ANSI escapes")
	}
}

func TestExplainMultipleAndMissing(t *testing.T) {
	out, stderr, err := run(t, "4624", "12345")
	if !errors.Is(err, errNotFound) {
		t.Fatalf("expected errNotFound, got %v", err)
	}
	if !strings.Contains(out, "4624") {
		t.Error("found IDs should still be printed")
	}
	if !strings.Contains(stderr, "no entry for event ID 12345") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestExplainRejectsNonNumeric(t *testing.T) {
	_, _, err := run(t, "logon")
	if err == nil || !strings.Contains(err.Error(), "weix search logon") {
		t.Fatalf("expected a search hint, got %v", err)
	}
}

func TestExplainJSON(t *testing.T) {
	out, _, err := run(t, "4769", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got []struct {
		ID     int    `json:"id"`
		Source string `json:"source"`
		MITRE  []struct {
			ID, Name, URL string
		} `json:"mitre"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(got) != 1 || got[0].ID != 4769 || got[0].Source != "Security" {
		t.Fatalf("unexpected JSON: %+v", got)
	}
	if got[0].MITRE[0].URL != "https://attack.mitre.org/techniques/T1558/003/" {
		t.Errorf("technique URL = %s", got[0].MITRE[0].URL)
	}
}

func TestChannelFlag(t *testing.T) {
	out, _, err := run(t, "1", "--channel", "sysmon")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Process creation") {
		t.Errorf("expected Sysmon process creation, got:\n%s", out)
	}
}

func TestSearchCmd(t *testing.T) {
	out, _, err := run(t, "search", "kerberoasting")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "4769") {
		t.Errorf("search output missing 4769:\n%s", out)
	}
	if _, _, err := run(t, "search", "nothing-matches-this"); !errors.Is(err, errNotFound) {
		t.Errorf("expected errNotFound for empty search, got %v", err)
	}
}

func TestListCmd(t *testing.T) {
	out, _, err := run(t, "list", "--category", "log-tampering")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1102") || !strings.Contains(out, "104") {
		t.Errorf("list output:\n%s", out)
	}
	out, _, err = run(t, "list", "--categories")
	if err != nil || !strings.Contains(out, "persistence") {
		t.Errorf("categories output %q, err %v", out, err)
	}
}

func TestLogonTypeCmd(t *testing.T) {
	out, _, err := run(t, "logon-type", "10")
	if err != nil || !strings.Contains(out, "RemoteInteractive") {
		t.Errorf("logon-type 10: %q %v", out, err)
	}
	if _, _, err := run(t, "logon-type", "42"); !errors.Is(err, errNotFound) {
		t.Errorf("expected errNotFound, got %v", err)
	}
	out, _, _ = run(t, "lt")
	if !strings.Contains(out, "NewCredentials") {
		t.Errorf("logon type table missing entries:\n%s", out)
	}
}

func TestStatusCmd(t *testing.T) {
	out, _, err := run(t, "status", "0xC0000234")
	if err != nil || !strings.Contains(out, "STATUS_ACCOUNT_LOCKED_OUT") {
		t.Errorf("status: %q %v", out, err)
	}
	out, _, err = run(t, "status", "0x18", "--json")
	if err != nil || !strings.Contains(out, "KDC_ERR_PREAUTH_FAILED") {
		t.Errorf("status json: %q %v", out, err)
	}
}
