package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MrWaifu24/weix/internal/events"
	"github.com/MrWaifu24/weix/internal/render"
)

func newSearchCmd(db *events.DB, opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "search <keyword>...",
		Short: "Search events by keyword, ATT&CK technique, field or category",
		Example: `  weix search kerberos
  weix search T1003
  weix search lsass dump
  weix search scheduled task`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var hits []*events.Event
			for _, e := range db.Search(strings.Join(args, " ")) {
				if e.MatchesChannel(opts.channel) {
					hits = append(hits, e)
				}
			}
			if opts.json {
				return render.JSON(cmd.OutOrStdout(), render.EventsJSON(db, hits))
			}
			opts.text(cmd.OutOrStdout(), db).Table(hits)
			if len(hits) == 0 {
				return errNotFound
			}
			return nil
		},
	}
}

func newListCmd(db *events.DB, opts *options) *cobra.Command {
	var category string
	var categories bool
	c := &cobra.Command{
		Use:   "list",
		Short: "List known events, optionally filtered by category or channel",
		Example: `  weix list
  weix list --category persistence
  weix list --channel sysmon
  weix list --categories`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if categories {
				counts := db.Categories()
				if opts.json {
					return render.JSON(out, counts)
				}
				opts.text(out, db).Categories(counts)
				return nil
			}
			evs := db.Filter(category, opts.channel)
			if opts.json {
				return render.JSON(out, render.EventsJSON(db, evs))
			}
			opts.text(out, db).Table(evs)
			if len(evs) == 0 {
				return errNotFound
			}
			return nil
		},
	}
	c.Flags().StringVar(&category, "category", "", "only list events in this category (see --categories)")
	c.Flags().BoolVar(&categories, "categories", false, "list categories with event counts")
	c.RegisterFlagCompletionFunc("category", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		var names []string
		for n := range db.Categories() {
			names = append(names, n)
		}
		sort.Strings(names)
		return names, cobra.ShellCompDirectiveNoFileComp
	})
	return c
}

func newLogonTypeCmd(db *events.DB, opts *options) *cobra.Command {
	return &cobra.Command{
		Use:     "logon-type [type]",
		Aliases: []string{"lt"},
		Short:   "Explain a LogonType value from 4624/4625 (lists all without an argument)",
		Example: "  weix logon-type 3\n  weix logon-type",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if len(args) == 0 {
				if opts.json {
					return render.JSON(out, db.LogonTypes)
				}
				opts.text(out, db).LogonTypes(db.LogonTypes)
				return nil
			}
			var n int
			if _, err := fmt.Sscanf(args[0], "%d", &n); err != nil {
				return fmt.Errorf("%q is not a logon type number", args[0])
			}
			lt, ok := db.LogonType(n)
			if !ok {
				fmt.Fprintf(cmd.ErrOrStderr(), "weix: unknown logon type %d - run `weix logon-type` to list all\n", n)
				return errNotFound
			}
			if opts.json {
				return render.JSON(out, lt)
			}
			opts.text(out, db).LogonType(lt)
			return nil
		},
	}
}

func newStatusCmd(db *events.DB, opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "status [code]",
		Short: "Explain an NTSTATUS / Kerberos failure code (lists all without an argument)",
		Long: `Explain failure codes from the Status/SubStatus fields of 4625 and 4776
(NTSTATUS, e.g. 0xC000006A) or the Status field of 4768/4769/4771
(Kerberos, e.g. 0x18).`,
		Example: "  weix status 0xC000006A\n  weix status 0x18\n  weix status",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if len(args) == 0 {
				if opts.json {
					return render.JSON(out, db.StatusCodes)
				}
				opts.text(out, db).StatusTable(db.StatusCodes)
				return nil
			}
			codes := db.Status(args[0])
			if len(codes) == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "weix: unknown status code %s - run `weix status` to list all\n", args[0])
				return errNotFound
			}
			if opts.json {
				return render.JSON(out, codes)
			}
			opts.text(out, db).Status(codes)
			return nil
		},
	}
}
