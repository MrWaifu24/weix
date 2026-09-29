// Package cmd implements the weix command-line interface.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MrWaifu24/weix/internal/events"
	"github.com/MrWaifu24/weix/internal/render"
)

type options struct {
	json    bool
	noColor bool
	channel string
	width   int
}

// errNotFound signals a clean "nothing matched" exit (status 1) after the
// command has already told the user what was missing.
var errNotFound = errors.New("not found")

// Execute runs the CLI and returns the process exit code.
func Execute(version string) int {
	db, err := events.Default()
	if err != nil {
		fmt.Fprintln(os.Stderr, "weix: failed to load knowledge base:", err)
		return 2
	}
	root := NewRootCmd(db, version)
	if err := root.Execute(); err != nil {
		if !errors.Is(err, errNotFound) {
			fmt.Fprintln(os.Stderr, "weix:", err)
		}
		return 1
	}
	return 0
}

// NewRootCmd builds the command tree around a loaded knowledge base.
func NewRootCmd(db *events.DB, version string) *cobra.Command {
	opts := &options{}

	root := &cobra.Command{
		Use:   "weix <event-id>...",
		Short: "Windows Event ID explainer for SOC analysts",
		Long: `weix explains Windows Event IDs in a SOC-friendly format: what the event
means, which log it lives in, why it matters for security, the fields to
inspect, investigation steps, common false positives and MITRE ATT&CK mapping.

Covers Security, System, PowerShell, Sysmon, Defender, RDP, Task Scheduler
and WMI events.`,
		Example: `  weix 4624
  weix 4625 4740 --json
  weix 1 --channel sysmon
  weix search kerberoasting
  weix list --category persistence
  weix logon-type 10
  weix status 0xC000006A`,
		Version:       version,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return runExplain(cmd, db, opts, args)
		},
	}

	root.PersistentFlags().BoolVar(&opts.json, "json", false, "output JSON")
	root.PersistentFlags().BoolVar(&opts.noColor, "no-color", false, "disable colored output (also honours NO_COLOR)")
	root.PersistentFlags().IntVar(&opts.width, "width", 88, "wrap text at this many columns")
	root.PersistentFlags().StringVarP(&opts.channel, "channel", "c", "", "only show events from a log/channel (e.g. security, sysmon, powershell)")

	root.AddCommand(
		newSearchCmd(db, opts),
		newListCmd(db, opts),
		newLogonTypeCmd(db, opts),
		newStatusCmd(db, opts),
	)
	return root
}

func (o *options) text(w io.Writer, db *events.DB) *render.Text {
	return &render.Text{W: w, Color: o.useColor(w), Width: o.width, DB: db}
}

func (o *options) useColor(w io.Writer) bool {
	if o.noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func runExplain(cmd *cobra.Command, db *events.DB, opts *options, args []string) error {
	out := cmd.OutOrStdout()
	var found []*events.Event
	var missing []string

	for _, a := range args {
		id, err := strconv.Atoi(strings.TrimSpace(a))
		if err != nil || id < 0 {
			return fmt.Errorf("%q is not an event ID (did you mean `weix search %s`?)", a, a)
		}
		matches := db.Lookup(id, opts.channel)
		if len(matches) == 0 {
			missing = append(missing, a)
			continue
		}
		found = append(found, matches...)
	}

	if opts.json {
		if err := render.JSON(out, render.EventsJSON(db, found)); err != nil {
			return err
		}
	} else {
		t := opts.text(out, db)
		for i, e := range found {
			if i > 0 {
				fmt.Fprintf(out, "\n\n")
			}
			t.Event(e)
		}
	}

	if len(missing) > 0 {
		scope := ""
		if opts.channel != "" {
			scope = fmt.Sprintf(" in channel %q", opts.channel)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "weix: no entry for event ID %s%s - try `weix search <keyword>` or `weix list`\n",
			strings.Join(missing, ", "), scope)
		return errNotFound
	}
	return nil
}
