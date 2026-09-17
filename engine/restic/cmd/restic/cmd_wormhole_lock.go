package main

import (
	"fmt"
	"io"

	"github.com/restic/restic/internal/global"
	"github.com/restic/restic/internal/ui/progress"
	"github.com/spf13/cobra"
)

func newWormholeLockCommand(globalOptions *global.Options) *cobra.Command {
	return &cobra.Command{
		Use:    "wormhole-lock",
		Short:  "Hold an exclusive repository lock for a Wormhole workflow",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if globalOptions.WormholeParentLock {
				return fmt.Errorf("wormhole-lock cannot inherit another repository lock")
			}
			printer := progress.NewTerminalPrinter(false, globalOptions.Verbosity, globalOptions.Term)
			ctx, _, unlock, err := internalOpenWithLocked(cmd.Context(), *globalOptions, false, true, printer)
			if err != nil {
				return err
			}
			defer unlock()

			if _, err := fmt.Fprintln(globalOptions.Term.OutputRaw(), "ready"); err != nil {
				return err
			}
			done := make(chan error, 1)
			go func() {
				_, err := io.Copy(io.Discard, globalOptions.Term.InputRaw())
				done <- err
			}()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-done:
				return err
			}
		},
	}
}
