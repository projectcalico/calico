// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/daemon"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

var versionFlag = flag.Bool("version", false, "Print version information")

func main() {
	flag.Parse()

	// For --version use case
	if *versionFlag {
		buildinfo.PrintVersion()
		os.Exit(0)
	}

	cfg, err := config.NewCalicoConfig()
	if err != nil {
		logrus.Fatal(err)
	}

	logrus.Infof("Starting Calico Guardian %s", cfg.String())
	daemon.Run(GetShutdownContext(), cfg.Config, cfg.Targets())
}

// GetShutdownContext creates a context that's done when either syscall.SIGINT or syscall.SIGTERM notified.
func GetShutdownContext() context.Context {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signalChan
		logrus.Debug("Shutdown signal received, shutting down.")
		cancel()
	}()

	return ctx
}
