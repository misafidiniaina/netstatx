package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/misafidiniaina/netstatx/internal/capture"
	"github.com/spf13/cobra"
)

var interfaceName string

var runCmd = &cobra.Command{
	Use: "run",
	RunE: func(cmd *cobra.Command, args []string) error {
		collector, err := capture.Start(interfaceName)
		if err != nil {
			return err
		}
		defer collector.Close()
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		fmt.Printf("capturing traffic on %s; press Ctrl-C to stop\n", interfaceName)
		<-ctx.Done()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&interfaceName, "interface", "i", "eth0", "network interface")
}
