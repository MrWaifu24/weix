// Package render formats knowledge-base entries for the terminal or as JSON.
package render

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/MrWaifu24/weix/internal/events"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
)

// Text renders human-readable output.
type Text struct {
	W     io.Writer
	Color bool
	Width int
	DB    *events.DB
}

func (t *Text) c(code, s string) string {
	if !t.Color {
		return s
	}
	return code + s + reset
}

func (t *Text) width() int {
	if t.Width < 40 {
		return 88
	}
	return t.Width
}

func (t *Text) criticality(level string) string {
	label := strings.ToUpper(level)
	switch level {
	case "high":
		return t.c(bold+red, label)
	case "medium":
		return t.c(yellow, label)
	case "low":
		return t.c(green, label)
	default:
		return t.c(dim, label)
	}
}

func (t *Text) heading(s string) {
	fmt.Fprintf(t.W, "\n%s\n", t.c(bold+cyan, s))
}

func (t *Text) para(s string) {
	for _, line := range wrap(s, t.width()-2) {
		fmt.Fprintf(t.W, "  %s\n", line)
	}
}

func (t *Text) bullets(items []string) {
	for _, it := range items {
		lines := wrap(it, t.width()-4)
		for i, line := range lines {
			prefix := "    "
			if i == 0 {
				prefix = "  • "
			}
			fmt.Fprintf(t.W, "%s%s\n", prefix, line)
		}
	}
}

// Event prints the full explanation of one event.
func (t *Text) Event(e *events.Event) {
	title := fmt.Sprintf("%d  %s", e.ID, e.Name)
	fmt.Fprintf(t.W, "%s\n", t.c(bold, title))
	fmt.Fprintf(t.W, "%s\n", t.c(dim, strings.Repeat("─", min(utf8.RuneCountInString(title), t.width()))))

	kv := func(k, v string) { fmt.Fprintf(t.W, "  %-12s %s\n", t.c(dim, k), v) }
	kv("Log", e.Channel)
	kv("Provider", e.Provider)
	kv("Category", e.Category)
	kv("Criticality", t.criticality(e.Criticality))
	if len(e.MITRE) > 0 {
		for i, id := range e.MITRE {
			label := ""
			if i == 0 {
				label = "ATT&CK"
			}
			name := t.DB.Technique(id)
			fmt.Fprintf(t.W, "  %-12s %s  %s\n", t.c(dim, label), t.c(yellow, id), name)
		}
	}

	t.heading("WHAT IT MEANS")
	t.para(e.Description)

	t.heading("WHY IT MATTERS")
	t.para(e.Relevance)

	if len(e.Fields) > 0 {
		t.heading("KEY FIELDS")
		for _, f := range e.Fields {
			fmt.Fprintf(t.W, "  %s\n", t.c(bold, f.Name))
			for _, line := range wrap(f.Note, t.width()-6) {
				fmt.Fprintf(t.W, "      %s\n", line)
			}
		}
	}

	if len(e.Investigate) > 0 {
		t.heading("INVESTIGATION")
		t.bullets(e.Investigate)
	}

	if len(e.FalsePositives) > 0 {
		t.heading("COMMON FALSE POSITIVES")
		t.bullets(e.FalsePositives)
	}

	if e.Detection != "" {
		t.heading("DETECTION IDEA")
		t.para(e.Detection)
	}

	if len(e.Related) > 0 {
		t.heading("RELATED")
		for _, id := range e.Related {
			for _, r := range t.DB.Lookup(id, "") {
				fmt.Fprintf(t.W, "  %-6s %-14s %s\n", t.c(bold, strconv.Itoa(r.ID)), r.Source(), r.Name)
			}
		}
	}
}

// Table prints a compact one-line-per-event listing.
func (t *Text) Table(evs []*events.Event) {
	if len(evs) == 0 {
		fmt.Fprintln(t.W, "no matching events")
		return
	}
	fmt.Fprintf(t.W, "%s\n", t.c(bold, fmt.Sprintf("%-6s %-20s %-8s %s", "ID", "LOG", "LEVEL", "NAME")))
	for _, e := range evs {
		name := truncate(e.Name, t.width()-37)
		level := fmt.Sprintf("%-8s", strings.ToUpper(e.Criticality))
		if t.Color {
			level = t.criticality(e.Criticality) + strings.Repeat(" ", 8-len(e.Criticality))
		}
		fmt.Fprintf(t.W, "%-6d %-20s %s %s\n", e.ID, e.Source(), level, name)
	}
	fmt.Fprintf(t.W, "%s\n", t.c(dim, fmt.Sprintf("\n%d event(s). Run `weix <id>` for details.", len(evs))))
}

// Categories prints each category with its event count.
func (t *Text) Categories(counts map[string]int) {
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(t.W, "  %-20s %d\n", n, counts[n])
	}
}

// LogonType prints one logon type explanation.
func (t *Text) LogonType(lt events.LogonType) {
	fmt.Fprintf(t.W, "%s\n", t.c(bold, fmt.Sprintf("Logon type %d - %s", lt.Type, lt.Name)))
	t.para(lt.Description)
	if lt.Notes != "" {
		fmt.Fprintln(t.W)
		for _, line := range wrap("SOC note: "+lt.Notes, t.width()-2) {
			fmt.Fprintf(t.W, "  %s\n", t.c(yellow, line))
		}
	}
}

// LogonTypes prints the full logon type table.
func (t *Text) LogonTypes(lts []events.LogonType) {
	fmt.Fprintf(t.W, "%s\n", t.c(bold, fmt.Sprintf("%-5s %-24s %s", "TYPE", "NAME", "DESCRIPTION")))
	for _, lt := range lts {
		fmt.Fprintf(t.W, "%-5d %-24s %s\n", lt.Type, lt.Name, truncate(lt.Description, t.width()-31))
	}
}

// Status prints one or more failure-code explanations.
func (t *Text) Status(codes []events.StatusCode) {
	for i, sc := range codes {
		if i > 0 {
			fmt.Fprintln(t.W)
		}
		fmt.Fprintf(t.W, "%s  %s  %s\n", t.c(bold, sc.Code), t.c(cyan, sc.Name), t.c(dim, "("+kindLabel(sc.Kind)+")"))
		t.para(sc.Meaning)
		if sc.Notes != "" {
			for _, line := range wrap("SOC note: "+sc.Notes, t.width()-2) {
				fmt.Fprintf(t.W, "  %s\n", t.c(yellow, line))
			}
		}
	}
}

// StatusTable prints all known failure codes.
func (t *Text) StatusTable(codes []events.StatusCode) {
	fmt.Fprintf(t.W, "%s\n", t.c(bold, fmt.Sprintf("%-12s %-9s %s", "CODE", "KIND", "MEANING")))
	for _, sc := range codes {
		fmt.Fprintf(t.W, "%-12s %-9s %s\n", sc.Code, sc.Kind, truncate(sc.Meaning, t.width()-23))
	}
}

func kindLabel(kind string) string {
	switch kind {
	case "ntstatus":
		return "NTSTATUS - 4625 / 4776"
	case "kerberos":
		return "Kerberos - 4768 / 4769 / 4771"
	}
	return kind
}

func truncate(s string, n int) string {
	if n < 4 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// wrap breaks s into lines of at most width runes on word boundaries.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if utf8.RuneCountInString(line)+1+utf8.RuneCountInString(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(lines, line)
}
