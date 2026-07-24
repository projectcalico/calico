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

package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
)

func newGetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [KIND [NAME...]]",
		Short: "Get a resource by file, directory, stdin, or type and name",
		Long: `Get one or more Calico resources - all resources of a type, specific ones by
name, or those described in a file. Output can be a table (the default), YAML,
JSON, or a custom template; the YAML and JSON output can be fed back into apply
or replace.`,
		Example: `  # List all network policies.
  calicoctl get networkpolicy

  # Get specific policies as YAML.
  calicoctl get networkpolicy my-policy-1 my-policy-2 -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)

			allNamespaces := allNamespacesRequested(cmd)
			parsedArgs["--all-namespaces"] = allNamespaces
			export, _ := cmd.Flags().GetBool("export")
			parsedArgs["--export"] = export

			output, _ := cmd.Flags().GetString("output")
			parsedArgs["--output"] = output

			namespace, _ := cmd.Flags().GetString("namespace")
			printNamespace := allNamespaces || namespace != ""

			rp, err := buildResourcePrinter(output, printNamespace)
			if err != nil {
				return err
			}

			results := common.ExecuteConfigCommand(parsedArgs, common.ActionGetOrList)
			logrus.Infof("results: %+v", results)

			if results.FileInvalid {
				return fmt.Errorf("failed to execute command: %v", results.Err)
			} else if results.Err != nil {
				return fmt.Errorf("failed to get resources: %v", results.Err)
			}

			if err := rp.Print(results.Client, results.Resources); err != nil {
				return err
			}

			if len(results.ResErrs) > 0 {
				var errStr strings.Builder
				for i, err := range results.ResErrs {
					errStr.WriteString(err.Error())
					if (i + 1) != len(results.ResErrs) {
						errStr.WriteString("\n")
					}
				}
				return errors.New(errStr.String())
			}

			return nil
		},
	}
	addCRUDFlags(cmd)
	cmd.Flags().StringP("output", "o", "ps", "Output format: yaml, json, ps, wide, custom-columns=..., go-template=..., go-template-file=...")
	cmd.Flags().BoolP("all-namespaces", "A", false, "List the requested object(s) across all namespaces.")
	// calicoctl historically accepted -a as well as -A (a docopt quirk locked in by
	// TestMultiOption); cobra allows one shorthand per flag, so register -a as a hidden alias.
	cmd.Flags().BoolP("all-namespaces-a", "a", false, "Alias for --all-namespaces.")
	_ = cmd.Flags().MarkHidden("all-namespaces-a")
	cmd.Flags().Bool("export", false, "Strip cluster-specific information from the output.")
	return cmd
}

// allNamespacesRequested reports whether the user asked to list across all
// namespaces, accepting both -A and the historical -a alias.
func allNamespacesRequested(cmd *cobra.Command) bool {
	if a, _ := cmd.Flags().GetBool("all-namespaces"); a {
		return true
	}
	aAlias, _ := cmd.Flags().GetBool("all-namespaces-a")
	return aAlias
}

func buildResourcePrinter(output string, printNamespace bool) (common.ResourcePrinter, error) {
	switch output {
	case "yaml", "yml":
		return common.ResourcePrinterYAML{}, nil
	case "json":
		return common.ResourcePrinterJSON{}, nil
	case "ps":
		return common.ResourcePrinterTable{Wide: false, PrintNamespace: printNamespace}, nil
	case "wide":
		return common.ResourcePrinterTable{Wide: true, PrintNamespace: printNamespace}, nil
	}

	// Output format may be a key=value pair.
	outputParms := strings.SplitN(output, "=", 2)
	outputKey := outputParms[0]
	outputValue := ""
	var outputValues []string
	if len(outputParms) == 2 {
		outputValue = outputParms[1]
		outputValues = strings.Split(outputValue, ",")
	}

	switch outputKey {
	case "go-template":
		if outputValue == "" {
			return nil, fmt.Errorf("need to specify a template")
		}
		return common.ResourcePrinterTemplate{Template: outputValue}, nil
	case "go-template-file":
		if outputValue == "" {
			return nil, fmt.Errorf("need to specify a template file")
		}
		return common.ResourcePrinterTemplateFile{TemplateFile: outputValue}, nil
	case "custom-columns":
		if outputValue == "" {
			return nil, fmt.Errorf("need to specify at least one column")
		}
		return common.ResourcePrinterTable{Headings: outputValues}, nil
	}

	return nil, fmt.Errorf("unrecognized output format '%s'", output)
}

// addConfigFlag adds just the --config flag. Used by commands that need
// config but not the full CRUD flag set.
func addConfigFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("config", "c", constants.DefaultConfigPath, "Path to the file containing connection configuration in YAML or JSON format.")
}
