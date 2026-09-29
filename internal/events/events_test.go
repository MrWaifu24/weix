package events

import (
	"regexp"
	"slices"
	"testing"
	"testing/fstest"
)

func loadDB(t *testing.T) *DB {
	t.Helper()
	db, err := Default()
	if err != nil {
		t.Fatalf("load embedded knowledge base: %v", err)
	}
	return db
}

var (
	techniqueRE  = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	validChannel = map[string]bool{
		"Security":           true,
		"System":             true,
		"Windows PowerShell": true,
		"Microsoft-Windows-PowerShell/Operational":                               true,
		"Microsoft-Windows-Sysmon/Operational":                                   true,
		"Microsoft-Windows-Windows Defender/Operational":                         true,
		"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": true,
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational":     true,
		"Microsoft-Windows-TaskScheduler/Operational":                            true,
		"Microsoft-Windows-WMI-Activity/Operational":                             true,
	}
)

// TestDatasetIntegrity guards the quality of the curated knowledge base.
func TestDatasetIntegrity(t *testing.T) {
	db := loadDB(t)

	if len(db.Events) < 70 {
		t.Errorf("expected at least 70 events, got %d", len(db.Events))
	}

	for _, e := range db.Events {
		if e.Name == "" || e.Provider == "" || e.Description == "" || e.Relevance == "" || e.Category == "" {
			t.Errorf("%d/%s: name, provider, description, relevance and category are required", e.ID, e.Channel)
		}
		if !validChannel[e.Channel] {
			t.Errorf("%d: unexpected channel %q", e.ID, e.Channel)
		}
		if !slices.Contains(Criticalities, e.Criticality) {
			t.Errorf("%d/%s: criticality %q not in %v", e.ID, e.Channel, e.Criticality, Criticalities)
		}
		if len(e.Fields) == 0 {
			t.Errorf("%d/%s: at least one key field is required", e.ID, e.Channel)
		}
		for _, f := range e.Fields {
			if f.Name == "" || f.Note == "" {
				t.Errorf("%d/%s: field entries need a name and a note", e.ID, e.Channel)
			}
		}
		if len(e.Investigate) == 0 {
			t.Errorf("%d/%s: at least one investigation step is required", e.ID, e.Channel)
		}
		if len(e.FalsePositives) == 0 {
			t.Errorf("%d/%s: at least one false-positive note is required", e.ID, e.Channel)
		}
		for _, m := range e.MITRE {
			if !techniqueRE.MatchString(m) {
				t.Errorf("%d/%s: malformed ATT&CK ID %q", e.ID, e.Channel, m)
			}
			if db.Technique(m) == "" {
				t.Errorf("%d/%s: ATT&CK ID %s has no name in mitre.yaml", e.ID, e.Channel, m)
			}
		}
		for _, r := range e.Related {
			if r == e.ID {
				t.Errorf("%d/%s: event lists itself as related", e.ID, e.Channel)
			}
			if len(db.Lookup(r, "")) == 0 {
				t.Errorf("%d/%s: related event %d is not in the knowledge base", e.ID, e.Channel, r)
			}
		}
	}
}

func TestLookupTablesComplete(t *testing.T) {
	db := loadDB(t)
	for _, n := range []int{2, 3, 4, 5, 7, 8, 9, 10, 11} {
		if _, ok := db.LogonType(n); !ok {
			t.Errorf("logon type %d missing", n)
		}
	}
	for _, sc := range db.StatusCodes {
		if sc.Kind != "ntstatus" && sc.Kind != "kerberos" {
			t.Errorf("status %s: unknown kind %q", sc.Code, sc.Kind)
		}
		if sc.Name == "" || sc.Meaning == "" {
			t.Errorf("status %s: name and meaning are required", sc.Code)
		}
	}
}

func TestLookup(t *testing.T) {
	db := loadDB(t)

	got := db.Lookup(4624, "")
	if len(got) != 1 || got[0].Name != "An account was successfully logged on" {
		t.Fatalf("Lookup(4624) = %+v", got)
	}
	if got := db.Lookup(1, "sysmon"); len(got) != 1 || got[0].Source() != "Sysmon" {
		t.Errorf("Lookup(1, sysmon) = %+v", got)
	}
	if got := db.Lookup(4624, "sysmon"); len(got) != 0 {
		t.Errorf("Lookup(4624, sysmon) should be empty, got %d", len(got))
	}
	if got := db.Lookup(99999, ""); len(got) != 0 {
		t.Errorf("Lookup(99999) should be empty")
	}
}

func TestLookupMultipleChannels(t *testing.T) {
	fsys := fstest.MapFS{
		"events/a.yaml": {Data: []byte(`
- {id: 1, channel: Security, provider: p, name: first, category: c, criticality: low, description: d, relevance: r}
- {id: 1, channel: "Microsoft-Windows-Sysmon/Operational", provider: p, name: second, category: c, criticality: low, description: d, relevance: r}
`)},
		"logon_types.yaml":  {Data: []byte("[]")},
		"status_codes.yaml": {Data: []byte("[]")},
		"mitre.yaml":        {Data: []byte("{}")},
	}
	db, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup(1, ""); len(got) != 2 {
		t.Fatalf("expected both channels for ID 1, got %d", len(got))
	}
	if got := db.Lookup(1, "security"); len(got) != 1 || got[0].Name != "first" {
		t.Errorf("channel filter failed: %+v", got)
	}
}

func TestLoadRejectsDuplicates(t *testing.T) {
	entry := "- {id: 5, channel: Security, provider: p, name: n, category: c, criticality: low, description: d, relevance: r}\n"
	fsys := fstest.MapFS{
		"events/a.yaml":     {Data: []byte(entry + entry)},
		"logon_types.yaml":  {Data: []byte("[]")},
		"status_codes.yaml": {Data: []byte("[]")},
		"mitre.yaml":        {Data: []byte("{}")},
	}
	if _, err := Load(fsys); err == nil {
		t.Fatal("expected an error for duplicate id+channel")
	}
}

func TestSearch(t *testing.T) {
	db := loadDB(t)
	cases := []struct {
		query string
		want  int // ID expected among the results
		first bool
	}{
		{"kerberoasting", 4769, true},
		{"lsass", 10, false},
		{"T1053.005", 4698, false},
		{"scheduled task created", 4698, true},
		{"dcsync", 4662, true},
		{"4104", 4104, true},
	}
	for _, c := range cases {
		hits := db.Search(c.query)
		if len(hits) == 0 {
			t.Errorf("Search(%q) returned nothing", c.query)
			continue
		}
		if c.first && hits[0].ID != c.want {
			t.Errorf("Search(%q) first hit = %d, want %d", c.query, hits[0].ID, c.want)
		}
		found := false
		for _, h := range hits {
			found = found || h.ID == c.want
		}
		if !found {
			t.Errorf("Search(%q) missing %d", c.query, c.want)
		}
	}
	if hits := db.Search("definitely-not-a-real-term"); len(hits) != 0 {
		t.Errorf("expected no hits, got %d", len(hits))
	}
	if hits := db.Search("kerberos zzzz"); len(hits) != 0 {
		t.Errorf("all terms must match, got %d hits", len(hits))
	}
}

func TestStatus(t *testing.T) {
	db := loadDB(t)
	for _, in := range []string{"0xC000006A", "0xc000006a", "C000006A", " 0xC000006A "} {
		got := db.Status(in)
		if len(got) != 1 || got[0].Name != "STATUS_WRONG_PASSWORD" {
			t.Errorf("Status(%q) = %+v", in, got)
		}
	}
	if got := db.Status("0x00000018"); len(got) != 1 || got[0].Kind != "kerberos" {
		t.Errorf("Status(0x00000018) = %+v", got)
	}
	if got := db.Status("zz"); got != nil {
		t.Errorf("Status(zz) should be nil")
	}
}

func TestFilter(t *testing.T) {
	db := loadDB(t)
	for _, e := range db.Filter("persistence", "") {
		if e.Category != "persistence" {
			t.Errorf("%d has category %s", e.ID, e.Category)
		}
	}
	sysmon := db.Filter("", "sysmon")
	if len(sysmon) == 0 {
		t.Fatal("no sysmon events")
	}
	for _, e := range sysmon {
		if e.Source() != "Sysmon" {
			t.Errorf("%d is from %s", e.ID, e.Source())
		}
	}
}
