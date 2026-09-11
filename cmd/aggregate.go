package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/misafidiniaina/netstatx/internal/aggregator"
	"github.com/spf13/cobra"
)

var mapPath string

var aggregateCmd = &cobra.Command{
	Use: "aggregate",
	RunE: func(cmd *cobra.Command, args []string) error {

		if mapPath == "" {
			return fmt.Errorf("--map required")
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		agg := aggregator.NewDNSAggregator()

		go func() {
			if err := aggregator.StartMapReader(mapPath, agg); err != nil {
				log.Println("reader error:", err)
			}
		}()

		ticker := time.NewTicker(5 * time.Second)

		for {
			select {
			case <-ctx.Done():
				return nil

			case <-ticker.C:
				fmt.Println("---- DNS ----")
				for ip, cnt := range agg.Snapshot() {
					fmt.Printf("%d -> %d\n", ip, cnt)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(aggregateCmd)
	aggregateCmd.Flags().StringVar(&mapPath, "map", "", "pinned map path")
}