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

package commands

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	logLevel string
)

var rootCmd = &cobra.Command{
	Use:   "calico-qos",
	Short: "tool for monitoring Calico QoS bandwidth usage",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(setLogLevel)
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "warn", "Set log level")
	rootCmd.SetOut(os.Stdout)
}

func setLogLevel() {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.WarnLevel
	}
	log.SetLevel(level)
}
