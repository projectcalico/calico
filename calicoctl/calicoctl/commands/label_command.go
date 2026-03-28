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
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
)

func newLabelCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "label KIND NAME [key=value | key]",
		Short: "Add or update labels of resources",
		Args:  cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			overwrite, _ := cmd.Flags().GetBool("overwrite")
			remove, _ := cmd.Flags().GetBool("remove")
			config, _ := cmd.Flags().GetString("config")
			namespace, _ := cmd.Flags().GetString("namespace")

			kind := args[0]
			name := args[1]
			labelArg := args[2]

			// Build the bridge args map for ExecuteConfigCommand.
			parsedArgs := map[string]any{
				"<KIND>":                    kind,
				"<NAME>":                    []string{name},
				"--config":                  config,
				"--namespace":               namespace,
				"--context":                 nil,
				"--allow-version-mismatch":  false,
				"--filename":                nil,
				"--recursive":               false,
				"--skip-empty":              false,
			}
			if v, _ := cmd.Root().Flags().GetString("context"); v != "" {
				parsedArgs["--context"] = v
			}
			if v, _ := cmd.Root().Flags().GetBool("allow-version-mismatch"); v {
				parsedArgs["--allow-version-mismatch"] = true
			}
			if namespace == "" {
				parsedArgs["--namespace"] = nil
			}

			// Parse key/value.
			var key, value string
			if remove {
				key = labelArg
			} else {
				kv := strings.SplitN(labelArg, "=", 2)
				if len(kv) != 2 {
					return fmt.Errorf("invalid label %s", labelArg)
				}
				key = kv[0]
				value = kv[1]
			}

			logrus.Debugf("label args: kind=%s name=%s key=%s value=%s remove=%v overwrite=%v", kind, name, key, value, remove, overwrite)

			results := common.ExecuteConfigCommand(parsedArgs, common.ActionGetOrList)
			if results.FileInvalid {
				return fmt.Errorf("failed to execute command: %v", results.Err)
			} else if results.Err != nil {
				return fmt.Errorf("failed to get %s %s, error %v", kind, name, results.Err)
			} else if len(results.Resources) == 0 {
				return fmt.Errorf("%s %s not found", kind, name)
			}

			resource := results.Resources[0].(resourcemgr.ResourceObject)
			labels := resource.GetObjectMeta().GetLabels()
			client := results.Client
			if labels == nil {
				labels = make(map[string]string)
			}

			overwritten := false
			if remove {
				if _, ok := labels[key]; !ok {
					return fmt.Errorf("cannot remove label of %s %s, key %s does not exist", kind, name, key)
				}
				delete(labels, key)
			} else {
				oldValue, ok := labels[key]
				if ok {
					if overwrite || value == oldValue {
						labels[key] = value
						overwritten = true
					} else {
						return fmt.Errorf("failed to update label of %s %s, key %s is already present. please use '--overwrite' to set a new value", kind, name, key)
					}
				} else {
					labels[key] = value
				}
			}

			resource.GetObjectMeta().SetLabels(labels)
			_, err := common.ExecuteResourceAction(parsedArgs, client, resource, common.ActionUpdate)
			if err != nil {
				return fmt.Errorf("failed to update %s %s, label not changed", kind, name)
			}

			if remove {
				fmt.Printf("Successfully removed label %s from %s %s\n", key, kind, name)
			} else if overwritten {
				fmt.Printf("Successfully updated label %s on %s %s\n", key, kind, name)
			} else {
				fmt.Printf("Successfully set label %s on %s %s\n", key, kind, name)
			}
			return nil
		},
	}
	cmd.Flags().StringP("config", "c", constants.DefaultConfigPath, "Path to the file containing connection configuration in YAML or JSON format.")
	cmd.Flags().StringP("namespace", "n", "", "Namespace of the resource.")
	cmd.Flags().Bool("overwrite", false, "Overwrite the value when the key is already present in labels.")
	cmd.Flags().Bool("remove", false, "Remove the specified key from labels.")
	return cmd
}
