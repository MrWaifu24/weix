package render

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/MrWaifu24/weix/internal/events"
)

// Technique is an ATT&CK technique reference in JSON output.
type Technique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// EventJSON is the JSON representation of an event, with ATT&CK names and
// links resolved so the output is useful without the knowledge base.
type EventJSON struct {
	*events.Event
	Source string      `json:"source"`
	MITRE  []Technique `json:"mitre"`
}

// NewEventJSON enriches an event for JSON output.
func NewEventJSON(db *events.DB, e *events.Event) EventJSON {
	out := EventJSON{Event: e, Source: e.Source(), MITRE: []Technique{}}
	for _, id := range e.MITRE {
		out.MITRE = append(out.MITRE, Technique{ID: id, Name: db.Technique(id), URL: TechniqueURL(id)})
	}
	return out
}

// TechniqueURL returns the attack.mitre.org page for a technique ID.
func TechniqueURL(id string) string {
	return "https://attack.mitre.org/techniques/" + strings.Replace(id, ".", "/", 1) + "/"
}

// JSON writes v as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// EventsJSON converts a list of events for JSON output.
func EventsJSON(db *events.DB, evs []*events.Event) []EventJSON {
	out := make([]EventJSON, 0, len(evs))
	for _, e := range evs {
		out = append(out, NewEventJSON(db, e))
	}
	return out
}
