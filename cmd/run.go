package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/misafidiniaina/netstatx/internal/capture"

	"github.com/spf13/cobra"
)

var iface string

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start network traffic capture",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("Starting capture on interface:", iface)

		// ---- graceful shutdown context ----
		ctx, stop := signal.NotifyContext(
			context.Background(),
			os.Interrupt,
			syscall.SIGTERM,
		)
		defer stop()

		// ---- start TC collector ----
		collector, err := capture.Start(iface)
		if err != nil {
			return err
		}
		defer collector.Close()

		// ---- polling loop ----
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("Stopping capture")
				return nil

			case <-ticker.C:
				flows, err := collector.Snapshot()
				if err != nil {
					log.Println("snapshot error:", err)
					continue
				}

				if len(flows) == 0 {
					continue
				}

				fmt.Println("\n=== Traffic Summary ===")
				for _, f := range flows {
					dir := "RX ←"
					if f.Direction == 1 {
						dir = "TX →"
					}
					fmt.Printf("%-15s %s %10s\n",
						f.IP.String(),
						dir,
						formatBytes(f.Bytes),
					)
				}
			}
		}
	},
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(bytes)/float64(div),
		"KMGTPE"[exp])
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVar(&iface, "iface", "eth0", "Network interface")
}