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

// Tool to generate combined metadata for hte Felix configuration parameters.
// It combines information from Felix's internal model along with the
// documentation from the CRDs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
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

	fmt.Println("This file was generated by `calico-felix-docgen`. Do not edit directly.")
	fmt.Println()
	fmt.Println("## Sections")
	for _, groupName := range groupNames {
		fmt.Printf("* [%s](#%s)\n", groupName, nameToAnchor(groupName))
	}
	fmt.Println()
	for _, groupName := range groupNames {
		fmt.Printf("## <a id=\"%s\">%s\n", nameToAnchor(groupName), groupName)
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

func nameToAnchor(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	name = regexp.MustCompile(`[^a-z-]`).ReplaceAllString(name, "")
	return name
}

func collectGroups(params []*config.FieldInfo) (map[string][]*config.FieldInfo, []string) {
	groups := map[string][]*config.FieldInfo{}
	groupNamesWithSortPrefix := set.New[string]()
	for _, param := range params {
		groupNamesWithSortPrefix.Add(param.GroupWithSortPrefix)
		groups[param.Group] = append(groups[param.Group], param)
	}
	groupNamesWithSortPrefixSlice := groupNamesWithSortPrefix.Slice()
	sort.Strings(groupNamesWithSortPrefixSlice)

	// Strip off the sort-order prefix.
	var groupNames []string
	for _, g := range groupNamesWithSortPrefixSlice {
		groupNames = append(groupNames, strings.TrimLeft(g, " 0123456789"))
	}

	return groups, groupNames
}

func outputGroups(params []*config.FieldInfo) {
	groups, groupNames := collectGroups(params)
	for _, groupName := range groupNames {
		fmt.Printf("## %s\n", groupName)
		fmt.Println()
		for _, param := range groups[groupName] {
			fmt.Printf("* %s\n", param.NameConfigFile)
		}
		fmt.Println()
	}
}

func outputMissingDescriptions(params []*config.FieldInfo) {
	var printErrorOnce sync.Once
	groups, groupNames := collectGroups(params)
	someMissing := false
	for _, groupName := range groupNames {
		var printGroupOnce sync.Once
		needSpace := false
		for _, param := range groups[groupName] {
			if param.Description != "" {
				continue
			}
			printErrorOnce.Do(func() {
				someMissing = true
				fmt.Println()
				fmt.Println("Warning: Unable to find documentation for some Felix configuration fields.")
				fmt.Println("Please add docs either to the FelixConfigurationSpec or, for local-only ")
				fmt.Println("parameters, to the config.Config struct.")
				fmt.Println()
			})
			printGroupOnce.Do(func() {
				fmt.Printf("## %s\n", groupName)
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

	if someMissing {
		os.Exit(1)
	}
}

type OutputJSON struct {
	Comment string
	Groups  []Group
}

type Group struct {
	Name   string
	Fields []*config.FieldInfo
}

func outputJSON(params []*config.FieldInfo) {
	var groups []Group
	groupsByName, groupNames := collectGroups(params)
	for _, g := range groupNames {
		groups = append(groups, Group{
			Name:   g,
			Fields: groupsByName[g],
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(OutputJSON{
		Comment: "This file generated by calico-felix-docgen, DO NOT EDIT.",
		Groups:  groups,
	})
	if err != nil {
		logrus.WithError(err).Fatal("Failed to encode JSON")
	}
}
