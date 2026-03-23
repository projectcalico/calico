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
	"os"
	"runtime"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/cli"
	"k8s.io/component-base/logs"

	"github.com/projectcalico/calico/apiserver/cmd/apiserver/server"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

func newAPIServerCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "apiserver",
		Short:              "Run the Calico API server",
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			logs.InitLogs()
			defer logs.FlushLogs()

			err := feature.DefaultMutableFeatureGate.SetFromMap(map[string]bool{
				string(features.WatchList): false,
			})
			if err != nil {
				logrus.WithError(err).Error("Error setting feature gates")
				logs.FlushLogs()
				os.Exit(1)
			}

			if len(os.Getenv("GOMAXPROCS")) == 0 {
				runtime.GOMAXPROCS(runtime.NumCPU())
			}

			buildinfo.PrintVersion()

			serverCmd, _, err := server.NewCommandStartCalicoServer(os.Stdout)
			if err != nil {
				logrus.WithError(err).Error("Error creating server")
				logs.FlushLogs()
				os.Exit(1)
			}

			serverCmd.SetArgs(args)
			code := cli.Run(serverCmd)
			os.Exit(code)
		},
	}
}
