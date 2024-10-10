// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var format = flag.String("format", "json", "Output format, one of json, md.")
var logLevel = flag.String("log-level", "fatal", "Log level, one of fatal, error, info, debug, etc.")

func main() {
	flag.Parse()
	configureLogging()

	params, err := config.CombinedFieldInfo()
	if err != nil {
		logrus.Fatalf("Failed to load param metadata: %v", err)
	}

	switch *format {
	case "json":
		outputJSON(params)
	case "md":
		outputMarkdown(params)
	case "groups":
		outputGroups(params)
	case "missing":
		outputMissingDescriptions(params)
	default:
		logrus.Fatalf("Unknown format: %v", *format)
	}
}

func configureLogging() {
	logutils.ConfigureFormatter("docgen")
	logrus.SetLevel(logrus.FatalLevel)
	logLevel, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("Failed to parse log level: %v", err)
	}
	logrus.SetLevel(logLevel)
}

func outputMarkdown(params []*config.FieldInfo) {
	groups, groupNames := collectGroups(params)

	for _, groupName := range groupNames {
		fmt.Printf("## %s\n", strings.TrimLeft(groupName, " 0123456789"))
		fmt.Println()
		for _, param := range groups[groupName] {
			name := fmt.Sprintf("`%s` (config file / env var only)", param.NameConfigFile)
			if param.NameGoAPI != "" {
				name = fmt.Sprintf("`%s` (config file) / `%s` (YAML)", param.NameConfigFile, param.NameYAML)
			}
			fmt.Printf("### %s\n", name)
			fmt.Println()
			fmt.Println(param.Description)
			fmt.Println()
			fmt.Printf("| Detail |   |\n")
			fmt.Printf("| --- | --- |\n")
			fmt.Printf("| Environment variable | `%s` |\n", param.NameEnvVar)
			fmt.Printf("| Encoding (env var/config file) | %s |\n", strings.ReplaceAll(param.StringSchema, "|", "\\|"))
			if param.StringDefault != "" {
				fmt.Printf("| Default value (above encoding) | `%s` |\n", strings.ReplaceAll(param.StringDefault, "|", "\\|"))
			} else {
				fmt.Printf("| Default value (above encoding) | none |\n")
			}
			if param.NameYAML != "" {
				fmt.Printf("| `FelixConfiguration` field | `%s` (YAML) `%s` (Go API) |\n", param.NameYAML, param.NameGoAPI)
				if param.YAMLSchema != "" {
					fmt.Printf("| `FelixConfiguration` schema | %s |\n", strings.ReplaceAll(param.YAMLSchema, "|", "\\|"))
				} else if param.YAMLType != "" {
					fmt.Printf("| `FelixConfiguration` schema | `%s` |\n", param.YAMLType)
				}
			}
			var notes []string
			if param.Required {
				notes = append(notes, "required")
			}
			if param.AllowedConfigSources == config.AllowedConfigSourcesLocalOnly {
				notes = append(notes, "config file / env var only")
			}
			if param.OnParseFailure == "Exit" {
				notes = append(notes, "Felix will exit if the value is invalid")
			}
			if !param.UserEditable {
				notes = append(notes, "internal configuration, not intended to be edited by the user")
			}
			if len(notes) > 0 {
				note := strings.Join(notes, ", ")
				note = strings.ToUpper(note[0:1]) + note[1:] + "."
				fmt.Printf("| Notes | %s | \n", note)
			}
			fmt.Println()
		}
	}
}

func collectGroups(params []*config.FieldInfo) (map[string][]*config.FieldInfo, []string) {
	groups := map[string][]*config.FieldInfo{}
	for _, param := range params {
		groups[param.Group] = append(groups[param.Group], param)
	}
	var groupNames []string
	for groupName := range groups {
		groupNames = append(groupNames, groupName)
	}
	sort.Strings(groupNames)
	return groups, groupNames
}

func outputGroups(params []*config.FieldInfo) {
	groups, groupNames := collectGroups(params)
	for _, groupName := range groupNames {
		fmt.Printf("## %s\n", strings.TrimLeft(groupName, " 0123456789"))
		fmt.Println()
		for _, param := range groups[groupName] {
			fmt.Printf("* %s\n", param.NameConfigFile)
		}
		fmt.Println()
	}
}

func outputMissingDescriptions(params []*config.FieldInfo) {
	groups, groupNames := collectGroups(params)
	for _, groupName := range groupNames {
		var printGroupOnce sync.Once
		needSpace := false
		for _, param := range groups[groupName] {
			if param.Description != "" {
				continue
			}
			printGroupOnce.Do(func() {
				fmt.Printf("## %s\n", strings.TrimLeft(groupName, " 0123456789"))
				fmt.Println()
				needSpace = true
			})
			fmt.Printf("* %s", param.NameConfigFile)
			if param.AllowedConfigSources == config.AllowedConfigSourcesLocalOnly {
				fmt.Printf(" (config file / env var only)")
			}
			fmt.Println()
		}
		if needSpace {
			fmt.Println()
		}
	}
}

func outputJSON(params []*config.FieldInfo) {
	eng := json.NewEncoder(os.Stdout)
	eng.SetIndent("", "  ")
	err := eng.Encode(params)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to encode JSON")
	}
}
