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
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			parsedArgs["--skip-exists"], _ = cmd.Flags().GetBool("skip-exists")
			return createOrApplyOrReplace(parsedArgs, "create")
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
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			return createOrApplyOrReplace(parsedArgs, "apply")
		},
	}
	addCRUDFlags(cmd)
	return cmd
}

func newReplaceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replace",
		Short: "Replace a resource by file, directory or stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			return createOrApplyOrReplace(parsedArgs, "replace")
		},
	}
	addCRUDFlags(cmd)
	return cmd
}

func newValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a resource by file, directory or stdin without applying it",
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedArgs := argsFromCRUDFlags(cmd, args)
			return createOrApplyOrReplace(parsedArgs, "validate")
		},
	}
	addCRUDFlags(cmd)
	return cmd
}

// createOrApplyOrReplace executes create, apply, replace, or validate using
// the bridge args map and handles result formatting.
func createOrApplyOrReplace(args map[string]any, action string) error {
	results := executeForAction(args, action)
	if results == nil {
		return fmt.Errorf("unknown action: %s", action)
	}

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
			fmt.Printf("Successfully %sed %d '%s' resource(s)\n", action, results.NumHandled, results.SingleKind)
		} else {
			fmt.Printf("Successfully %sed %d resource(s)\n", action, results.NumHandled)
		}
	} else {
		if results.NumHandled-len(results.ResErrs) > 0 {
			fmt.Printf("Partial success: ")
			if results.SingleKind != "" {
				fmt.Printf("%sed the first %d out of %d '%s' resources:\n", action, results.NumHandled, results.NumResources, results.SingleKind)
			} else {
				fmt.Printf("%sed the first %d out of %d resources:\n", action, results.NumHandled, results.NumResources)
			}
		}
		return fmt.Errorf("hit error: %v", results.ResErrs)
	}

	return nil
}

func newDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [KIND [NAME...]]",
		Short: "Delete a resource by file, directory, stdin, or type and name",
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
		Args:  cobra.ExactArgs(2),
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
// action is unknown.
func executeForAction(args map[string]any, action string) *common.CommandResults {
	var r common.CommandResults
	switch action {
	case "create":
		r = common.ExecuteConfigCommand(args, common.ActionCreate)
	case "apply":
		r = common.ExecuteConfigCommand(args, common.ActionApply)
	case "replace":
		r = common.ExecuteConfigCommand(args, common.ActionUpdate)
	case "validate":
		r = common.ExecuteConfigCommand(args, common.ActionValidate)
	default:
		return nil
	}
	logrus.Infof("results: %+v", r)
	return &r
}
