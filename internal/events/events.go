// Package events loads and queries the weix Windows event knowledge base.
package events

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/MrWaifu24/weix/data"
)

// Field describes an event field worth inspecting during triage.
type Field struct {
	Name string `yaml:"name" json:"name"`
	Note string `yaml:"note" json:"note"`
}

// Event is a single knowledge-base entry for a Windows event ID in one channel.
type Event struct {
	ID             int      `yaml:"id" json:"id"`
	Channel        string   `yaml:"channel" json:"channel"`
	Provider       string   `yaml:"provider" json:"provider"`
	Name           string   `yaml:"name" json:"name"`
	Category       string   `yaml:"category" json:"category"`
	Criticality    string   `yaml:"criticality" json:"criticality"`
	Description    string   `yaml:"description" json:"description"`
	Relevance      string   `yaml:"relevance" json:"relevance"`
	MITRE          []string `yaml:"mitre" json:"mitre"`
	Fields         []Field  `yaml:"fields" json:"fields"`
	Investigate    []string `yaml:"investigate" json:"investigate"`
	FalsePositives []string `yaml:"false_positives" json:"false_positives"`
	Related        []int    `yaml:"related" json:"related"`
	Detection      string   `yaml:"detection,omitempty" json:"detection,omitempty"`
}

// LogonType explains a value of the LogonType field (4624/4625/4634).
type LogonType struct {
	Type        int    `yaml:"type" json:"type"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Notes       string `yaml:"notes" json:"notes"`
}

// StatusCode explains an NTSTATUS or Kerberos failure code.
type StatusCode struct {
	Code    string `yaml:"code" json:"code"`
	Kind    string `yaml:"kind" json:"kind"`
	Name    string `yaml:"name" json:"name"`
	Meaning string `yaml:"meaning" json:"meaning"`
	Notes   string `yaml:"notes" json:"notes"`
}

// Criticalities lists the allowed criticality values, lowest first.
var Criticalities = []string{"info", "low", "medium", "high"}

// DB is the in-memory knowledge base.
type DB struct {
	Events      []*Event
	LogonTypes  []LogonType
	StatusCodes []StatusCode
	Techniques  map[string]string

	byID map[int][]*Event
}

// Default loads the knowledge base embedded in the binary.
func Default() (*DB, error) {
	return Load(data.FS)
}

// Load reads a knowledge base from fsys, which must contain events/*.yaml,
// logon_types.yaml, status_codes.yaml and mitre.yaml.
func Load(fsys fs.FS) (*DB, error) {
	db := &DB{byID: map[int][]*Event{}}

	files, err := fs.Glob(fsys, "events/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		var evs []*Event
		if err := decode(fsys, f, &evs); err != nil {
			return nil, err
		}
		for _, e := range evs {
			e.normalize()
			db.Events = append(db.Events, e)
		}
	}

	if err := decode(fsys, "logon_types.yaml", &db.LogonTypes); err != nil {
		return nil, err
	}
	if err := decode(fsys, "status_codes.yaml", &db.StatusCodes); err != nil {
		return nil, err
	}
	if err := decode(fsys, "mitre.yaml", &db.Techniques); err != nil {
		return nil, err
	}
	for i := range db.LogonTypes {
		db.LogonTypes[i].Notes = clean(db.LogonTypes[i].Notes)
	}

	sort.SliceStable(db.Events, func(i, j int) bool {
		if db.Events[i].ID != db.Events[j].ID {
			return db.Events[i].ID < db.Events[j].ID
		}
		return db.Events[i].Channel < db.Events[j].Channel
	})

	seen := map[string]bool{}
	for _, e := range db.Events {
		key := fmt.Sprintf("%d|%s", e.ID, e.Channel)
		if seen[key] {
			return nil, fmt.Errorf("duplicate entry for event %d in channel %q", e.ID, e.Channel)
		}
		seen[key] = true
		db.byID[e.ID] = append(db.byID[e.ID], e)
	}
	return db, nil
}

func decode(fsys fs.FS, name string, v any) error {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path.Base(name), err)
	}
	return nil
}

// clean collapses the trailing newline left by YAML folded scalars.
func clean(s string) string { return strings.TrimSpace(s) }

func (e *Event) normalize() {
	e.Name = clean(e.Name)
	e.Description = clean(e.Description)
	e.Relevance = clean(e.Relevance)
	e.Detection = clean(e.Detection)
	e.Category = strings.ToLower(clean(e.Category))
	e.Criticality = strings.ToLower(clean(e.Criticality))
}

// Source returns a short, human-friendly label for the event's channel.
func (e *Event) Source() string { return ShortChannel(e.Channel) }

// ShortChannel maps a full channel name to a compact label.
func ShortChannel(channel string) string {
	switch {
	case channel == "Security", channel == "System":
		return channel
	case strings.Contains(channel, "Sysmon"):
		return "Sysmon"
	case channel == "Windows PowerShell":
		return "PowerShell (classic)"
	case strings.Contains(channel, "PowerShell"):
		return "PowerShell"
	case strings.Contains(channel, "Windows Defender"):
		return "Defender"
	case strings.Contains(channel, "RemoteConnectionManager"):
		return "RDP (RCM)"
	case strings.Contains(channel, "LocalSessionManager"):
		return "RDP (LSM)"
	case strings.Contains(channel, "TaskScheduler"):
		return "TaskScheduler"
	case strings.Contains(channel, "WMI-Activity"):
		return "WMI"
	}
	return channel
}

// MatchesChannel reports whether filter (case-insensitive) matches the
// event's full or short channel name. An empty filter matches everything.
func (e *Event) MatchesChannel(filter string) bool {
	if filter == "" {
		return true
	}
	f := strings.ToLower(filter)
	return strings.Contains(strings.ToLower(e.Channel), f) ||
		strings.Contains(strings.ToLower(e.Source()), f) ||
		strings.Contains(strings.ToLower(e.Provider), f)
}

// Lookup returns every entry for id, optionally restricted to a channel.
func (db *DB) Lookup(id int, channel string) []*Event {
	var out []*Event
	for _, e := range db.byID[id] {
		if e.MatchesChannel(channel) {
			out = append(out, e)
		}
	}
	return out
}

// Filter returns events matching the given category and channel filters.
func (db *DB) Filter(category, channel string) []*Event {
	var out []*Event
	for _, e := range db.Events {
		if category != "" && !strings.EqualFold(e.Category, category) {
			continue
		}
		if !e.MatchesChannel(channel) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Categories returns each category with the number of events in it.
func (db *DB) Categories() map[string]int {
	out := map[string]int{}
	for _, e := range db.Events {
		out[e.Category]++
	}
	return out
}

// Technique returns the ATT&CK name for a technique ID, if known.
func (db *DB) Technique(id string) string { return db.Techniques[id] }

// LogonType returns the explanation for a logon type number.
func (db *DB) LogonType(n int) (LogonType, bool) {
	for _, lt := range db.LogonTypes {
		if lt.Type == n {
			return lt, true
		}
	}
	return LogonType{}, false
}

// Status looks up a failure code. Input is hex with or without the 0x
// prefix, in any case, with or without leading zeros (0xC000006A,
// c000006a, 0x00000018 ...).
func (db *DB) Status(code string) []StatusCode {
	want, ok := parseHex(code)
	if !ok {
		return nil
	}
	var out []StatusCode
	for _, sc := range db.StatusCodes {
		if v, ok := parseHex(sc.Code); ok && v == want {
			out = append(out, sc)
		}
	}
	return out
}

func parseHex(s string) (uint64, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 64)
	return v, err == nil
}
