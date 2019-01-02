// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calicoctl/calicoctl/resourcemgr"

	log "github.com/sirupsen/logrus"
)

func Label(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl label (<KIND> <NAME> 
  	              ( <key>=<value> [--overwrite] |
  	                <key> --remove )
                  [--config=<CONFIG>] [--namespace=<NS>])
                  



Examples:
  # Label a workload endpoint
  calicoctl label workloadendpoints nginx --namespace=default app=web

  # Label a node and overwrite the original value of key 'cluster'
  calicoctl label nodes node1 cluster=frontend --overwrite

  # Remove label with key 'cluster' of the node
  calicoctl label nodes node1 cluster --remove

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
  -n --namespace=<NS>          Namespace of the resource.
                               Only applicable to NetworkPolicy and WorkloadEndpoint.
                               Uses the default namespace if not specified.
  --overwrite                  If true, overwrite the value when the key is already
                               present in labels. Otherwise reports error when the
                               labeled resource already have the key in its labels.
                               Can not be used with --remove.
  --remove                     If true, remove the specified key in labels of the
                               resource. Reports error when specified key does not
                               exist. Can not be used with --overwrite.

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

	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		fmt.Printf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	if len(parsedArgs) == 0 {
		return
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
			fmt.Printf("invalid label %s\n", parsedArgs["<key>=<value>"])
			os.Exit(1)
		}
		key = kv[0]
		value = kv[1]
	}

	// TODO: add more validation on key/value?

	results := executeConfigCommand(parsedArgs, actionGetOrList)
	if results.fileInvalid {
		fmt.Printf("Failed to execute command: %v\n", results.err)
		os.Exit(1)
	} else if results.err != nil {
		fmt.Printf("failed to get %s %s, error %v\n",
			kind, name, results.err)
		os.Exit(1)
	} else if len(results.resources) == 0 {
		fmt.Printf("%s %s not found\n", kind, name)
		os.Exit(1)
	}

	resource := results.resources[0].(resourcemgr.ResourceObject)
	labels := resource.GetObjectMeta().GetLabels()
	overwrite := parsedArgs["--overwrite"].(bool)
	overwritten := false
	client := results.client
	if labels == nil {
		labels = make(map[string]string)
	}

	if remove {
		// remove label.
		_, ok := labels[key]
		if !ok {
			// raise error if the key does not exist.
			fmt.Printf("can not remove label of %s %s, key %s does not exist\n",
				kind, name, key)
			os.Exit(1)
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
				fmt.Printf("failed to update label of %s %s, key %s is already present. please use '--overwrite' to set a new value.\n",
					kind, name, key)
				os.Exit(1)
			}
		} else {
			labels[key] = value
		}
	}

	resource.GetObjectMeta().SetLabels(labels)
	_, err = executeResourceAction(parsedArgs, client, resource, actionUpdate)
	if err != nil {
		fmt.Printf("failed to update %s %s, label not changed\n", kind, name)
		os.Exit(1)
	}

	if remove {
		fmt.Printf("label %s is removed from %s %s\n", key, kind, name)
	} else if overwritten {
		fmt.Printf("label %s of %s %s is overwitten\n", key, kind, name)
	} else {
		fmt.Printf("label %s of %s %s is set\n", key, kind, name)
	}
	return
}
