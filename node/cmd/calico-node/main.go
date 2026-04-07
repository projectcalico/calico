// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"

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
	"github.com/projectcalico/calico/node/pkg/nodeservices"
	"github.com/projectcalico/calico/node/pkg/status"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

// Create a new flag set.
var flagSet = flag.NewFlagSet("Calico", flag.ContinueOnError)

var version = flagSet.Bool("v", false, "Display version")

// Consolidated node services mode.
var runNodeServices = flagSet.Bool(
	"node-services",
	false,
	"Run consolidated node services (complete-startup, tunnel-ip-allocator, monitor-addresses, node-status-reporter, cni-config-monitor)",
)

// Deprecated flags: these are superseded by -node-services but kept for backwards
// compatibility. They will be removed in a future release.
var (
	monitorAddrs      = flagSet.Bool("monitor-addresses", false, "Deprecated: use -node-services instead.")
	monitorToken      = flagSet.Bool("monitor-token", false, "Deprecated: use -node-services instead.")
	runStatusReporter = flagSet.Bool("status-reporter", false, "Deprecated: use -node-services instead.")
)

// Felix flags.
var (
	runFelix = flagSet.Bool("felix", false, "Run Felix")
	runBPF   = flagSet.Bool("bpf", false, "Run BPF debug tool")

	// For watching node flowlogs.
	flows = flagSet.Int("flows", 0, "Fetch a number of Flows. Use a negative value to watch forever.")
)

// Node init, startup, and shutdown flags.
var (
	runInit       = flagSet.Bool("init", false, "Do privileged initialisation of a new node (mount file systems etc).")
	bestEffort    = flagSet.Bool("best-effort", false, "Used in combination with the init flag. Report errors but do not fail if an error occurs during initialisation.")
	initHostpaths = flagSet.Bool("hostpath-init", false, "Initialize hostpaths for non-root access")

	runStartup      = flagSet.Bool("startup", false, "Do non-privileged start-up routine.")
	runShutdown     = flagSet.Bool("shutdown", false, "Do shutdown routine.")
	completeStartup = flagSet.Bool("complete-startup", false, "Update the NetworkUnavailable condition in Kubernetes on successful startup.")
)

// Tunnel IP allocation flags.
var (
	runAllocateTunnelAddrs     = flagSet.Bool("allocate-tunnel-addrs", false, "Configure tunnel addresses for this node")
	allocateTunnelAddrsRunOnce = flagSet.Bool("allocate-tunnel-addrs-run-once", false, "Run allocate-tunnel-addrs in oneshot mode")
)

var (
	// Options for liveness checks.
	felixLive = flagSet.Bool("felix-live", false, "Run felix liveness checks")
	birdLive  = flagSet.Bool("bird-live", false, "Run bird liveness checks")
	bird6Live = flagSet.Bool("bird6-live", false, "Run bird6 liveness checks")

	// Options for readiness checks.
	birdReady  = flagSet.Bool("bird-ready", false, "Run BIRD readiness checks")
	bird6Ready = flagSet.Bool("bird6-ready", false, "Run BIRD6 readiness checks")
	felixReady = flagSet.Bool("felix-ready", false, "Run felix readiness checks")

	// thresholdTime for bird readiness check. Default value is 30 sec.
	thresholdTime = flagSet.Duration("threshold-time", 30*time.Second, "Threshold time for bird readiness")

	// Node status flags.
	showStatus = flagSet.Bool("show-status", false, "Print out node status")
)

// confd flags
var (
	runConfd     = flagSet.Bool("confd", false, "Run confd")
	confdRunOnce = flagSet.Bool("confd-run-once", false, "Run confd in oneshot mode")
	confdKeep    = flagSet.Bool("confd-keep-stage-file", false, "Keep stage file when running confd")
	confdConfDir = flagSet.String("confd-confdir", "/etc/calico/confd", "Confd configuration directory.")
)

func main() {
	// Log to stdout.  this prevents our logs from being interpreted as errors by, for example,
	// fluentd's default configuration.
	logrus.SetOutput(os.Stdout)

	// Set up logging formatting.
	logutils.ConfigureFormatter("node")

	// Parse the provided flags.
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Perform some validation on the parsed flags. Only one of the following may be
	// specified at a time.
	onlyOne := []*bool{version, runFelix, runStartup, runConfd, runNodeServices, monitorAddrs, monitorToken, runStatusReporter}
	oneSelected := false
	for _, o := range onlyOne {
		if oneSelected && *o {
			fmt.Println("More than one incompatible argument provided")
			os.Exit(1)
		}

		if *o {
			oneSelected = true
		}
	}

	// Check for liveness / readiness flags. Will only run checks specified by flags.
	if *felixLive || *birdReady || *bird6Ready || *felixReady || *birdLive || *bird6Live {
		health.Run(*birdReady, *bird6Ready, *felixReady, *felixLive, *birdLive, *bird6Live, *thresholdTime)
		os.Exit(0)
	}

	// Decide which action to take based on the given flags.
	if *version {
		buildinfo.PrintVersion()
		os.Exit(0)
	} else if *runFelix {
		logrus.SetFormatter(&logutils.Formatter{Component: "felix"})
		felix.Run("/etc/calico/felix.cfg", buildinfo.Version, buildinfo.BuildDate, buildinfo.GitRevision)
	} else if *runBPF {
		// Command-line tools should log to stderr to avoid confusion with the output.
		logrus.SetOutput(os.Stderr)
		bpf.RunBPFCmd()
	} else if *runInit {
		logrus.SetFormatter(&logutils.Formatter{Component: "init"})
		if *bestEffort {
			logrus.SetFormatter(&logutils.Formatter{Component: "init-best-effort"})
		}
		nodeinit.Run(*bestEffort)
	} else if *runStartup {
		logrus.SetFormatter(&logutils.Formatter{Component: "startup"})
		startup.Run()
		if *completeStartup {
			// If both --startup and --complete-startup are specified, then we immediately mark
			// the node as available after startup completes.  This skips readiness checks before
			// marking the node as available.
			if err = startup.MarkNetworkAvailable(); err != nil {
				utils.Terminate()
			}
		}
	} else if *runShutdown {
		logrus.SetFormatter(&logutils.Formatter{Component: "shutdown"})
		shutdown.Run()
	} else if *completeStartup {
		logrus.SetFormatter(&logutils.Formatter{Component: "complete-startup"})
		ctx := context.Background() // Context is never cancelled.
		if err := startup.ManageNodeCondition(ctx, 5*time.Minute); err != nil {
			utils.Terminate()
		}
	} else if *runConfd {
		logrus.SetFormatter(&logutils.Formatter{Component: "confd"})
		cfg, err := confdConfig.InitConfig(true)
		if err != nil {
			panic(err)
		}
		cfg.ConfDir = *confdConfDir
		cfg.KeepStageFile = *confdKeep
		cfg.Onetime = *confdRunOnce
		confd.Run(cfg)
	} else if *runAllocateTunnelAddrs {
		logutils.ConfigureFormatter("tunnel-ip-allocator")
		if *allocateTunnelAddrsRunOnce {
			allocateip.Run(nil)
		} else {
			logrus.Warn("-allocate-tunnel-addrs daemon mode is deprecated, use -node-services instead")
			if err := allocateip.RunWithContext(context.Background()); err != nil {
				logrus.WithError(err).Fatal("Tunnel IP allocator failed")
			}
		}
	} else if *runNodeServices {
		logutils.ConfigureFormatter("node-services")
		nodeservices.Run()
	} else if *monitorAddrs {
		logrus.Warn("-monitor-addresses is deprecated, use -node-services instead")
		logutils.ConfigureFormatter("monitor-addresses")
		startup.ConfigureLogging()
		if err := startup.MonitorIPAddressSubnetsWithContext(context.Background()); err != nil {
			logrus.WithError(err).Fatal("Monitor addresses failed")
		}
	} else if *monitorToken {
		logrus.Warn("-monitor-token is deprecated, use -node-services instead")
		logutils.ConfigureFormatter("cni-config-monitor")
		if err := cni.RunWithContext(context.Background()); err != nil {
			logrus.WithError(err).Fatal("CNI config monitor failed")
		}
	} else if *runStatusReporter {
		logrus.Warn("-status-reporter is deprecated, use -node-services instead")
		logutils.ConfigureFormatter("status-reporter")
		if err := status.RunWithContext(context.Background()); err != nil {
			logrus.WithError(err).Fatal("Status reporter failed")
		}
	} else if *initHostpaths {
		logrus.SetFormatter(&logutils.Formatter{Component: "hostpath-init"})
		hostpathinit.Run()
	} else if *showStatus {
		status.Show()
		os.Exit(0)
	} else if *flows != 0 {
		flowlogs.RunFlowsCmd(*flows)
	} else {
		fmt.Println("No valid options provided. Usage:")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
}
