package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestCobraPersistentPreRunEReceivesLeafCommand(t *testing.T) {
	var gotUse string

	root := &cobra.Command{
		Use: "root",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			gotUse = cmd.Use
			return nil
		},
	}

	child := &cobra.Command{Use: "child", RunE: func(_ *cobra.Command, _ []string) error { return nil }}
	child.Flags().String("foo", "", "")
	root.AddCommand(child)

	root.SetArgs([]string{"child", "--foo=bar"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotUse != "child" {
		t.Fatalf("expected PersistentPreRunE to receive leaf command, got %q", gotUse)
	}
}
