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

// addCRUDFlags adds the standard flags shared by create/apply/replace/delete/get/validate.
func addCRUDFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("filename", "f", "", "Filename to use to create/apply/replace/delete the resource. Use '-' for stdin.")
	cmd.Flags().BoolP("recursive", "R", false, "Process the filename specified in -f recursively.")
	cmd.Flags().Bool("skip-empty", false, "Do not error if files contain no data.")
	cmd.Flags().StringP("config", "c", constants.DefaultConfigPath, "Path to the file containing connection configuration in YAML or JSON format.")
	cmd.Flags().StringP("namespace", "n", "", "Namespace of the resource.")
}

func newCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a resource by file, directory or stdin",
		Long: `Create one or more Calico resources from a file, directory, or stdin, in YAML
or JSON format. Use create when you want the command to fail if a resource
already exists; use apply if you'd rather create-or-update.`,
		Example: `  # Create resources from a file.
  calicoctl create -f ./policy.yaml

  # Create resources from stdin.
  cat policy.json | calicoctl create -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			parsedArgs["--skip-exists"], _ = cmd.Flags().GetBool("skip-exists")
			return createOrApplyOrValidate(parsedArgs, "create")
		},
	}
	addCRUDFlags(cmd)
	cmd.Flags().Bool("skip-exists", false, "Skip over resources that already exist.")
	return cmd
}

func newApplyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a resource by file, directory or stdin",
		Long: `Create or update one or more Calico resources from a file, directory, or stdin,
in YAML or JSON format. Apply adds resources that don't exist yet and updates
those that do, so it's the right choice when you don't care whether the resource
is already present.`,
		Example: `  # Apply resources from a file.
  calicoctl apply -f ./policy.yaml

  # Apply resources from stdin.
  cat policy.json | calicoctl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			return createOrApplyOrValidate(parsedArgs, "apply")
		},
	}
	addCRUDFlags(cmd)
	return cmd
}

func newReplaceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replace",
		Short: "Replace a resource by file, directory or stdin",
		Long: `Replace one or more existing Calico resources from a file, directory, or stdin,
in YAML or JSON format. Replace fails if a resource doesn't already exist; use
apply if you want it created in that case.`,
		Example: `  # Replace resources from a file.
  calicoctl replace -f ./policy.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			results := common.ExecuteConfigCommand(parsedArgs, common.ActionUpdate)
			return reportReplaceResults(&results)
		},
	}
	addCRUDFlags(cmd)
	return cmd
}

func newValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a resource by file, directory or stdin without applying it",
		Long: `Validate one or more Calico resources from a file, directory, or stdin without
applying them. Validation runs entirely offline - checking syntax, structure,
and schema without touching the datastore - so it's useful for catching errors
before you apply resources to a cluster.`,
		Example: `  # Validate resources in a file.
  calicoctl validate -f ./policy.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			return createOrApplyOrValidate(parsedArgs, "validate")
		},
	}
	addCRUDFlags(cmd)
	return cmd
}

// pastTense maps an action verb to its past-tense form for user-facing
// messages. The original per-command code spelled these out (created,
// applied, validated); the verbs don't share a regular "+ed" ending so we
// can't derive them from the action.
var pastTense = map[string]string{
	"create":   "created",
	"apply":    "applied",
	"validate": "validated",
}

// createOrApplyOrValidate executes create, apply, or validate using the
// bridge args map and handles result formatting. These actions collect
// per-resource errors in results.ResErrs (see common.ExecuteConfigCommand);
// replace is handled separately by reportReplaceResults because update
// errors surface via results.Err instead.
func createOrApplyOrValidate(args map[string]any, action string) error {
	results := executeForAction(args, action)
	if results == nil {
		return fmt.Errorf("unknown action: %s", action)
	}
	past := pastTense[action]

	if results.FileInvalid {
		return fmt.Errorf("failed to execute command: %v", results.Err)
	} else if results.NumResources == 0 {
		if results.Err != nil {
			return results.Err
		}
		fmt.Println("No resources specified")
	} else if results.NumHandled == 0 {
		if results.NumResources == 1 {
			return fmt.Errorf("failed to %s '%s' resource: %v", action, results.SingleKind, results.ResErrs)
		} else if results.SingleKind != "" {
			return fmt.Errorf("failed to %s any '%s' resources: %v", action, results.SingleKind, results.ResErrs)
		} else {
			return fmt.Errorf("failed to %s any resources: %v", action, results.ResErrs)
		}
	} else if len(results.ResErrs) == 0 {
		if results.SingleKind != "" {
			fmt.Printf("Successfully %s %d '%s' resource(s)\n", past, results.NumHandled, results.SingleKind)
		} else {
			fmt.Printf("Successfully %s %d resource(s)\n", past, results.NumHandled)
		}
	} else {
		if results.NumHandled-len(results.ResErrs) > 0 {
			fmt.Printf("Partial success: ")
			if results.SingleKind != "" {
				fmt.Printf("%s the first %d out of %d '%s' resources:\n", past, results.NumHandled, results.NumResources, results.SingleKind)
			} else {
				fmt.Printf("%s the first %d out of %d resources:\n", past, results.NumHandled, results.NumResources)
			}
		}
		return fmt.Errorf("hit error: %v", results.ResErrs)
	}

	return nil
}

// reportReplaceResults formats the results of a replace (update). Unlike
// create/apply, ExecuteConfigCommand reports update failures in results.Err
// (it does not append to ResErrs and does not skip the failed resource), so
// a stale resource-version conflict must be detected via results.Err or it
// gets reported as success.
func reportReplaceResults(results *common.CommandResults) error {
	if results.FileInvalid {
		return fmt.Errorf("failed to execute command: %v", results.Err)
	} else if results.NumResources == 0 {
		if results.Err != nil {
			return results.Err
		}
		fmt.Println("No resources specified")
	} else if results.NumHandled == 0 {
		if results.NumResources == 1 {
			return fmt.Errorf("failed to replace '%s' resource: %v", results.SingleKind, results.Err)
		} else if results.SingleKind != "" {
			return fmt.Errorf("failed to replace any '%s' resources: %v", results.SingleKind, results.Err)
		} else {
			return fmt.Errorf("failed to replace any resources: %v", results.Err)
		}
	} else if results.Err == nil {
		if results.SingleKind != "" {
			fmt.Printf("Successfully replaced %d '%s' resource(s)\n", results.NumHandled, results.SingleKind)
		} else {
			fmt.Printf("Successfully replaced %d resource(s)\n", results.NumHandled)
		}
	} else {
		fmt.Printf("Partial success: ")
		if results.SingleKind != "" {
			fmt.Printf("replaced the first %d out of %d '%s' resources:\n", results.NumHandled, results.NumResources, results.SingleKind)
		} else {
			fmt.Printf("replaced the first %d out of %d resources:\n", results.NumHandled, results.NumResources)
		}
		return fmt.Errorf("hit error: %v", results.Err)
	}

	return nil
}

func newDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [KIND [NAME...]]",
		Short: "Delete a resource by file, directory, stdin, or type and name",
		Long: `Delete one or more Calico resources, either by type and name or from a file,
directory, or stdin. Deleting a resource that doesn't exist is treated as an
error unless --skip-not-exists is set.`,
		Example: `  # Delete specific policies by name.
  calicoctl delete networkpolicy foo bar

  # Delete the resources described in a file.
  calicoctl delete -f ./policy.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			parsedArgs["--skip-not-exists"], _ = cmd.Flags().GetBool("skip-not-exists")

			results := common.ExecuteConfigCommand(parsedArgs, common.ActionDelete)
			logrus.Infof("results: %+v", results)

			if results.FileInvalid {
				return fmt.Errorf("failed to execute command: %v", results.Err)
			} else if results.NumResources == 0 {
				if results.Err != nil {
					return results.Err
				}
				fmt.Println("No resources specified")
			} else if results.Err == nil && results.NumHandled > 0 {
				if results.SingleKind != "" {
					fmt.Printf("Successfully deleted %d '%s' resource(s)\n", results.NumHandled, results.SingleKind)
				} else {
					fmt.Printf("Successfully deleted %d resource(s)\n", results.NumHandled)
				}
			} else if results.Err != nil {
				return fmt.Errorf("hit error: %v", results.Err)
			}

			if len(results.ResErrs) > 0 {
				var errStr strings.Builder
				for _, err := range results.ResErrs {
					if results.SingleKind != "" {
						fmt.Fprintf(&errStr, "Failed to delete '%s' resource: %v\n", results.SingleKind, err)
					} else {
						fmt.Fprintf(&errStr, "Failed to delete resource: %v\n", err)
					}
				}
				return errors.New(errStr.String())
			}

			return nil
		},
	}
	addCRUDFlags(cmd)
	cmd.Flags().BoolP("skip-not-exists", "s", false, "Skip over resources that do not exist.")
	return cmd
}

func newPatchCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "patch KIND NAME",
		Short: "Patch a pre-existing resource in place",
		Long: `Patch a single existing Calico resource in place. Use patch to change specific
fields without supplying the whole resource, as you'd have to with replace.`,
		Example: `  # Set a route reflector cluster ID on a node.
  calicoctl patch node node-0 --patch '{"spec":{"bgp":{"routeReflectorClusterID":"224.0.0.1"}}}'`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			parsedArgs["--patch"], _ = cmd.Flags().GetString("patch")
			parsedArgs["--type"], _ = cmd.Flags().GetString("type")

			results := common.ExecuteConfigCommand(parsedArgs, common.ActionPatch)
			logrus.Infof("results: %+v", results)

			if results.NumResources == 0 {
				if results.Err != nil {
					return results.Err
				}
				return fmt.Errorf("no resources specified")
			} else if results.Err == nil && results.NumHandled > 0 {
				fmt.Printf("Successfully patched %d '%s' resource\n", results.NumHandled, results.SingleKind)
			} else if results.Err != nil {
				return fmt.Errorf("hit error: %v", results.Err)
			}

			if len(results.ResErrs) > 0 {
				var errStr strings.Builder
				for _, err := range results.ResErrs {
					fmt.Fprintf(&errStr, "Failed to patch '%s' resource: %v\n", results.SingleKind, err)
				}
				return errors.New(errStr.String())
			}

			return nil
		},
	}
	cmd.Flags().StringP("config", "c", constants.DefaultConfigPath, "Path to the file containing connection configuration in YAML or JSON format.")
	cmd.Flags().StringP("namespace", "n", "", "Namespace of the resource.")
	cmd.Flags().StringP("patch", "p", "", "Spec to use to patch the resource.")
	cmd.Flags().StringP("type", "t", "strategic", "Format of patch type: strategic, json, or merge.")
	return cmd
}

// executeForAction runs ExecuteConfigCommand for the named action, returning nil if the
// action is unknown. Replace is not handled here; it has its own result handling
// in newReplaceCommand because update errors surface differently (see reportReplaceResults).
func executeForAction(args map[string]any, action string) *common.CommandResults {
	var r common.CommandResults
	switch action {
	case "create":
		r = common.ExecuteConfigCommand(args, common.ActionCreate)
	case "apply":
		r = common.ExecuteConfigCommand(args, common.ActionApply)
	case "validate":
		r = common.ExecuteConfigCommand(args, common.ActionValidate)
	default:
		return nil
	}
	logrus.Infof("results: %+v", r)
	return &r
}
