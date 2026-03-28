// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	confdConfig "github.com/projectcalico/calico/confd/pkg/config"
	confd "github.com/projectcalico/calico/confd/pkg/run"
	felix "github.com/projectcalico/calico/felix/daemon"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/node/cmd/calico-node/bpf"
	"github.com/projectcalico/calico/node/pkg/allocateip"
	"github.com/projectcalico/calico/node/pkg/cni"
	"github.com/projectcalico/calico/node/pkg/flowlogs"
	"github.com/projectcalico/calico/node/pkg/health"
	"github.com/projectcalico/calico/node/pkg/hostpathinit"
	"github.com/projectcalico/calico/node/pkg/lifecycle/shutdown"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup"
	"github.com/projectcalico/calico/node/pkg/lifecycle/utils"
	"github.com/projectcalico/calico/node/pkg/nodeinit"
	"github.com/projectcalico/calico/node/pkg/status"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

// NewCommand returns a cobra command tree for calico-node operations.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node",
		Short: "Calico node agent operations",
	}

	cmd.AddCommand(
		newFelixCommand(),
		newConfdCommand(),
		newInitCommand(),
		newStartupCommand(),
		newShutdownCommand(),
		newMonitorAddressesCommand(),
		newAllocateTunnelAddrsCommand(),
		newMonitorTokenCommand(),
		newCompleteStartupCommand(),
		newHostpathInitCommand(),
		newHealthCommand(),
		newStatusCommand(),
		newBPFCommand(),
		newFlowsCommand(),
		newVersionCommand(),
	)

	return cmd
}

func newFelixCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "felix",
		Short: "Run the Felix policy agent",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "felix"})
			felix.Run("/etc/calico/felix.cfg", buildinfo.Version, buildinfo.BuildDate, buildinfo.GitRevision)
		},
	}
}

func newConfdCommand() *cobra.Command {
	var runOnce bool
	var keepStageFile bool
	var confDir string

	cmd := &cobra.Command{
		Use:   "confd",
		Short: "Run the confd configuration daemon",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "confd"})
			cfg, err := confdConfig.InitConfig(true)
			if err != nil {
				logrus.WithError(err).Fatal("Failed to initialize confd config")
			}
			cfg.ConfDir = confDir
			cfg.KeepStageFile = keepStageFile
			cfg.Onetime = runOnce
			confd.Run(cfg)
		},
	}

	cmd.Flags().BoolVar(&runOnce, "run-once", false, "Run confd in oneshot mode")
	cmd.Flags().BoolVar(&keepStageFile, "keep-stage-file", false, "Keep stage file when running confd")
	cmd.Flags().StringVar(&confDir, "confdir", "/etc/calico/confd", "Confd configuration directory")

	return cmd
}

func newInitCommand() *cobra.Command {
	var bestEffort bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Do privileged initialisation of a new node",
		Run: func(cmd *cobra.Command, args []string) {
			if bestEffort {
				logrus.SetFormatter(&logutils.Formatter{Component: "init-best-effort"})
			} else {
				logrus.SetFormatter(&logutils.Formatter{Component: "init"})
			}
			nodeinit.Run(bestEffort)
		},
	}

	cmd.Flags().BoolVar(&bestEffort, "best-effort", false, "Report errors but do not fail if an error occurs during initialisation")

	return cmd
}

func newStartupCommand() *cobra.Command {
	var completeStartup bool

	cmd := &cobra.Command{
		Use:   "startup",
		Short: "Do non-privileged start-up routine",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "startup"})
			startup.Run()
			if completeStartup {
				if err := startup.MarkNetworkAvailable(); err != nil {
					utils.Terminate()
				}
			}
		},
	}

	cmd.Flags().BoolVar(&completeStartup, "complete-startup", false, "Mark the node as available immediately after startup")

	return cmd
}

func newShutdownCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "shutdown",
		Short: "Do shutdown routine",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "shutdown"})
			shutdown.Run()
		},
	}
}

func newMonitorAddressesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "monitor-addresses",
		Short: "Monitor change in node IP addresses",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "monitor-addresses"})
			startup.ConfigureLogging()
			startup.MonitorIPAddressSubnets()
		},
	}
}

func newAllocateTunnelAddrsCommand() *cobra.Command {
	var runOnce bool

	cmd := &cobra.Command{
		Use:   "allocate-tunnel-addrs",
		Short: "Configure tunnel addresses for this node",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "tunnel-ip-allocator"})
			if runOnce {
				allocateip.Run(nil)
			} else {
				allocateip.Run(make(chan struct{}))
			}
		},
	}

	cmd.Flags().BoolVar(&runOnce, "run-once", false, "Run in oneshot mode")

	return cmd
}

func newMonitorTokenCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "monitor-token",
		Short: "Watch for Kubernetes token changes, update CNI config",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "cni-config-monitor"})
			cni.Run()
		},
	}
}

func newCompleteStartupCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "complete-startup",
		Short: "Update the NetworkUnavailable condition in Kubernetes on successful startup",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "complete-startup"})
			ctx := context.Background()
			if err := startup.ManageNodeCondition(ctx, 5*time.Minute); err != nil {
				utils.Terminate()
			}
		},
	}
}

func newHostpathInitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "hostpath-init",
		Short: "Initialize hostpaths for non-root access",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "hostpath-init"})
			hostpathinit.Run()
		},
	}
}

func newHealthCommand() *cobra.Command {
	var felixLive, felixReady bool
	var birdReady, bird6Ready bool
	var birdLive, bird6Live bool
	var thresholdTime time.Duration

	cmd := &cobra.Command{
		Use:   "health",
		Short: "Run node health checks",
		Run: func(cmd *cobra.Command, args []string) {
			health.Run(birdReady, bird6Ready, felixReady, felixLive, birdLive, bird6Live, thresholdTime)
		},
	}

	cmd.Flags().BoolVar(&felixLive, "felix-live", false, "Run felix liveness checks")
	cmd.Flags().BoolVar(&felixReady, "felix-ready", false, "Run felix readiness checks")
	cmd.Flags().BoolVar(&birdReady, "bird-ready", false, "Run BIRD readiness checks")
	cmd.Flags().BoolVar(&bird6Ready, "bird6-ready", false, "Run BIRD6 readiness checks")
	cmd.Flags().BoolVar(&birdLive, "bird-live", false, "Run BIRD liveness checks")
	cmd.Flags().BoolVar(&bird6Live, "bird6-live", false, "Run BIRD6 liveness checks")
	cmd.Flags().DurationVar(&thresholdTime, "threshold-time", 30*time.Second, "Threshold time for bird readiness")

	return cmd
}

func newStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Node status operations",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "report",
		Short: "Run node status reporter",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetFormatter(&logutils.Formatter{Component: "status-reporter"})
			status.Run()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print out node status",
		Run: func(cmd *cobra.Command, args []string) {
			status.Show()
		},
	})

	return cmd
}

func newBPFCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "bpf",
		Short:              "BPF debug tools",
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			logrus.SetOutput(os.Stderr)
			os.Args = append([]string{"calico-bpf"}, args...)
			bpf.RunBPFCmd()
		},
	}
}

func newFlowsCommand() *cobra.Command {
	var numFlows int

	cmd := &cobra.Command{
		Use:   "flows",
		Short: "Fetch or watch node flow logs",
		Run: func(cmd *cobra.Command, args []string) {
			if numFlows == 0 {
				fmt.Println("Specify --num (-n) with a positive number to fetch flows, or negative to watch")
				os.Exit(1)
			}
			flowlogs.RunFlowsCmd(numFlows)
		},
	}

	cmd.Flags().IntVarP(&numFlows, "num", "n", 0, "Number of flows to fetch (negative = watch forever)")

	return cmd
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			buildinfo.PrintVersion()
		},
	}
}
