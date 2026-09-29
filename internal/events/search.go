package events

import (
	"sort"
	"strconv"
	"strings"
)

// Search returns events matching every term in query, best matches first.
// Terms are matched case-insensitively against the event ID, name,
// category, channel, ATT&CK technique IDs and names, field names and the
// descriptive text. Matches in the name rank highest, then the ID, category
// and ATT&CK techniques, then the body text.
func (db *DB) Search(query string) []*Event {
	terms := strings.Fields(strings.ToLower(query))
	if len(terms) == 0 {
		return nil
	}

	type hit struct {
		e     *Event
		score int
	}
	var hits []hit
	for _, e := range db.Events {
		name := strings.ToLower(e.Name)
		strong := strings.ToLower(strings.Join([]string{
			strconv.Itoa(e.ID), e.Category, strings.Join(e.MITRE, " "), db.techniqueNames(e),
		}, " "))
		weak := strings.ToLower(strings.Join([]string{
			e.Channel, e.Provider, e.Description, e.Relevance, e.Detection,
			fieldNames(e), strings.Join(e.Investigate, " "),
		}, " "))

		score := 0
		for _, t := range terms {
			switch {
			case strings.Contains(name, t):
				score += 5
			case strings.Contains(strong, t):
				score += 3
			case strings.Contains(weak, t):
				score++
			default:
				score = -1
			}
			if score < 0 {
				break
			}
		}
		if score > 0 {
			hits = append(hits, hit{e, score})
		}
	}

	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	out := make([]*Event, len(hits))
	for i, h := range hits {
		out[i] = h.e
	}
	return out
}

func (db *DB) techniqueNames(e *Event) string {
	names := make([]string, 0, len(e.MITRE))
	for _, id := range e.MITRE {
		names = append(names, db.Techniques[id])
	}
	return strings.Join(names, " ")
}

func fieldNames(e *Event) string {
	names := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		names = append(names, f.Name)
	}
	return strings.Join(names, " ")
}
