package cmd

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/misafidiniaina/netstatx/internal/capture"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show live network usage grouped by remote host",
	RunE: func(cmd *cobra.Command, args []string) error {
		collector, err := capture.Start(interfaceName)
		if err != nil {
			return err
		}
		defer collector.Close()
		for {
			flows, err := collector.Snapshot()
			if err != nil {
				return err
			}
			fmt.Print("\033[2J\033[H")
			fmt.Printf("netstatx — %s\n\n", time.Now().Format(time.RFC1123))
			printFlows(flows)
			time.Sleep(2 * time.Second)
		}
	},
}

func printFlows(flows []capture.Flow) {
	rows := make(map[string]uint64)
	for _, flow := range flows {
		name := flow.IP.String()
		if hosts, err := net.LookupAddr(name); err == nil && len(hosts) > 0 {
			name = hosts[0]
		}
		rows[name] += flow.Bytes
	}
	type row struct {
		name  string
		bytes uint64
	}
	ordered := make([]row, 0, len(rows))
	for name, bytes := range rows {
		ordered = append(ordered, row{name, bytes})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].bytes > ordered[j].bytes })
	fmt.Printf("%-48s %12s\n", "REMOTE HOST / IP", "BYTES")
	for _, item := range ordered {
		fmt.Printf("%-48s %12s\n", item.name, formatBytes(item.bytes))
	}
}

func formatBytes(bytes uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(bytes)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	return fmt.Sprintf("%.2f %s", value, units[unit])
}

func init() { rootCmd.AddCommand(statusCmd) }
