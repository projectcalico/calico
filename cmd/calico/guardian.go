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

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/daemon"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

func newGuardianCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "guardian",
		Short: "Run the Guardian secure tunnel proxy",
		Run: func(cmd *cobra.Command, args []string) {
			if v, _ := cmd.Flags().GetBool("version"); v {
				buildinfo.PrintVersion()
				return
			}

			cfg, err := config.NewCalicoConfig()
			if err != nil {
				logrus.WithError(err).Fatal("Failed to load Guardian configuration")
			}

			logrus.Infof("Starting Calico Guardian %s", cfg.String())
			daemon.Run(shutdownContext(), cfg.Config, cfg.Targets())
		},
	}

	cmd.Flags().Bool("version", false, "Print version information")
	return cmd
}

func shutdownContext() context.Context {
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
