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
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/node/pkg/node"
)

func main() {
	logrus.SetOutput(os.Stdout)
	logutils.ConfigureFormatter("node")

	os.Args = translateArgs(os.Args)
	cmd := node.NewCommand()
	cmd.Use = "calico-node"
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// translateArgs converts legacy calico-node flag-style invocation to cobra subcommand style.
// For example, ["calico-node", "-felix"] becomes ["calico-node", "felix"].
// Health check flags are grouped under the "health" subcommand.
// Compound flags like "-allocate-tunnel-addrs-run-once" become "--run-once" on the subcommand.
func translateArgs(args []string) []string {
	if len(args) < 2 {
		return args
	}

	// If the first arg doesn't start with "-", it's already a subcommand.
	if !strings.HasPrefix(args[1], "-") {
		return args
	}

	// Health check flags get grouped under "health".
	healthFlags := map[string]string{
		"-felix-live":     "--felix-live",
		"-felix-ready":    "--felix-ready",
		"-bird-ready":     "--bird-ready",
		"-bird6-ready":    "--bird6-ready",
		"-bird-live":      "--bird-live",
		"-bird6-live":     "--bird6-live",
		"-threshold-time": "--threshold-time",
	}

	var healthArgs []string
	hasHealth := false
	for _, arg := range args[1:] {
		if flag, ok := healthFlags[arg]; ok {
			healthArgs = append(healthArgs, flag)
			hasHealth = true
		} else if strings.HasPrefix(arg, "-threshold-time=") {
			healthArgs = append(healthArgs, "--threshold-time="+strings.TrimPrefix(arg, "-threshold-time="))
			hasHealth = true
		}
	}
	if hasHealth {
		return append([]string{args[0], "health"}, healthArgs...)
	}

	// Simple flag-to-subcommand translations.
	translations := map[string][]string{
		"-v":                     {"version"},
		"-felix":                 {"felix"},
		"-confd":                 {"confd"},
		"-init":                  {"init"},
		"-startup":               {"startup"},
		"-shutdown":              {"shutdown"},
		"-monitor-addresses":     {"monitor-addresses"},
		"-allocate-tunnel-addrs": {"allocate-tunnel-addrs"},
		"-monitor-token":         {"monitor-token"},
		"-complete-startup":      {"complete-startup"},
		"-hostpath-init":         {"hostpath-init"},
		"-status-reporter":       {"status", "report"},
		"-show-status":           {"status", "show"},
		"-bpf":                   {"bpf"},
	}

	// Modifier flags that apply to specific subcommands.
	modifiers := map[string]string{
		"-best-effort":                    "--best-effort",
		"-confd-run-once":                 "--run-once",
		"-confd-keep-stage-file":          "--keep-stage-file",
		"-allocate-tunnel-addrs-run-once": "--run-once",
	}

	result := []string{args[0]}
	var trailing []string

	for _, arg := range args[1:] {
		if sub, ok := translations[arg]; ok {
			result = append(result, sub...)
		} else if mod, ok := modifiers[arg]; ok {
			trailing = append(trailing, mod)
		} else if strings.HasPrefix(arg, "-confd-confdir=") {
			trailing = append(trailing, "--confdir="+strings.TrimPrefix(arg, "-confd-confdir="))
		} else if arg == "-confd-confdir" {
			trailing = append(trailing, "--confdir")
		} else if strings.HasPrefix(arg, "-flows") {
			// -flows is a special case with a value.
			result = append(result, "flows")
		} else {
			// Pass through anything we don't recognize (e.g., flag values).
			trailing = append(trailing, arg)
		}
	}

	return append(result, trailing...)
}
