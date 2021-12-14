// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

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
	"strings"

	docopt "github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"

	log "github.com/sirupsen/logrus"
)

func Label(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> label (<KIND> <NAME>
  	              ( <key>=<value> [--overwrite] |
  	                <key> --remove )
                  [--config=<CONFIG>] [--namespace=<NS>] [--context=<context>]) [--allow-version-mismatch]




Examples:
  # Label a workload endpoint
  <BINARY_NAME> label workloadendpoints nginx --namespace=default app=web

  # Label a node and overwrite the original value of key 'cluster'
  <BINARY_NAME> label nodes node1 cluster=frontend --overwrite

  # Remove label with key 'cluster' of the node
  <BINARY_NAME> label nodes node1 cluster --remove

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
  -n --namespace=<NS>          Namespace of the resource.
                               Only applicable to NetworkPolicy, NetworkSet, and WorkloadEndpoint.
                               Uses the default namespace if not specified.
     --overwrite               If true, overwrite the value when the key is already
                               present in labels. Otherwise reports error when the
                               labeled resource already have the key in its labels.
                               Can not be used with --remove.
     --remove                  If true, remove the specified key in labels of the
                               resource. Reports error when specified key does not
                               exist. Can not be used with --overwrite.
     --context=<context>       The name of the kubeconfig context to use.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The label command is used to add or update a label on a resource. Resource types
  that can be labeled are:

    * bgpConfiguration
    * bgpPeer
    * felixConfiguration
    * globalNetworkPolicy
    * globalNetworkSet
    * hostEndpoint
    * ipPool
    * ipReservation
    * kubeControllersConfiguration
    * networkPolicy
    * node
    * profile
    * workloadEndpoint

  The resource type is case insensitive and may be pluralized.

  Attempting to label resources that do not exist will get an error.

  Attempting to remove a label that does not in the resource will get an error.

  When labeling a resource on an existing key:
  - gets an error if option --overwrite is not provided.
  - value of the key updates to specified value if option --overwrite is provided.
  `
	// Replace all instances of BINARY_NAME with the name of the binary.
	binaryName, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", binaryName)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}
	if context := parsedArgs["--context"]; context != nil {
		os.Setenv("K8S_CURRENT_CONTEXT", context.(string))
	}

	log.Debugf("parse args: %+v\n", parsedArgs)
	// get results.
	kind := parsedArgs["<KIND>"].(string)
	name := parsedArgs["<NAME>"].(string)
	// TODO: convert kind into the formal format

	// parse key/value.
	var key, value string
	remove := parsedArgs["--remove"].(bool)
	if remove {
		key = parsedArgs["<key>"].(string)
	} else {
		kv := strings.Split(parsedArgs["<key>=<value>"].(string), "=")
		if len(kv) != 2 {
			return fmt.Errorf("invalid label %s", parsedArgs["<key>=<value>"])
		}
		key = kv[0]
		value = kv[1]
	}

	// TODO: add more validation on key/value?

	results := common.ExecuteConfigCommand(parsedArgs, common.ActionGetOrList)
	if results.FileInvalid {
		return fmt.Errorf("Failed to execute command: %v", results.Err)
	} else if results.Err != nil {
		return fmt.Errorf("failed to get %s %s, error %v",
			kind, name, results.Err)
	} else if len(results.Resources) == 0 {
		return fmt.Errorf("%s %s not found", kind, name)
	}

	resource := results.Resources[0].(resourcemgr.ResourceObject)
	labels := resource.GetObjectMeta().GetLabels()
	overwrite := parsedArgs["--overwrite"].(bool)
	overwritten := false
	client := results.Client
	if labels == nil {
		labels = make(map[string]string)
	}

	if remove {
		// remove label.
		_, ok := labels[key]
		if !ok {
			// raise error if the key does not exist.
			return fmt.Errorf("can not remove label of %s %s, key %s does not exist",
				kind, name, key)
		} else {
			delete(labels, key)
		}
	} else {
		// add or update label.
		oldValue, ok := labels[key]
		if ok {
			if overwrite || value == oldValue {
				labels[key] = value
				overwritten = true
			} else {
				return fmt.Errorf("failed to update label of %s %s, key %s is already present. please use '--overwrite' to set a new value.",
					kind, name, key)
			}
		} else {
			labels[key] = value
		}
	}

	resource.GetObjectMeta().SetLabels(labels)
	_, err = common.ExecuteResourceAction(parsedArgs, client, resource, common.ActionUpdate)
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
}
