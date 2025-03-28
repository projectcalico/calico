// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile  string
	logLevel string

	ipv6 *bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "calico-bpf",
	Short: "tool for interrogating Calico BPF state",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig, setLogLevel)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default is $HOME/.calico-bpf.yaml)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "warn", "Set log level")

	ipv6 = rootCmd.PersistentFlags().BoolP("ipv6", "6", false, "Use IPv6 instead of IPv4")
	rootCmd.SetOut(os.Stdout)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".calico-bpf" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".calico-bpf")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func makeDocUsage(cmd *cobra.Command) string {
	return fmt.Sprintf("Usage:\n\t%s\n\n", cmd.Use)
}

func setLogLevel() {
	var err error
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.WarnLevel
	}
	log.SetLevel(level)
}
