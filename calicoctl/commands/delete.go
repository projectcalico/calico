// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"github.com/docopt/docopt-go"

	"fmt"

	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/api/unversioned"
	"github.com/tigera/libcalico-go/lib/client"
	"github.com/tigera/libcalico-go/lib/errors"
)

func Delete(args []string) error {
	doc := EtcdIntro + `Delete a resource identified by file, stdin or resource type and name.

Usage:
  calicoctl delete [--skip-not-exists] (([--hostname=<HOSTNAME>] <KIND> <NAME>) | --filename=<FILE>) [--config=<CONFIG>]

Examples:
  # Delete a policy using the type and name specified in policy.yaml.
  calicoctl delete -f ./policy.yaml

  # Delete a policy based on the type and name in the YAML passed into stdin.
  cat policy.yaml | calicoctl delete -f -

  # Delete policy with name "foo"
  calicoctl delete policy foo

Options:
  -s --skip-not-exists         Skip over and treat as successful, resources that don't exist.
  -f --filename=<FILENAME>     Filename to use to delete the resource.  If set to "-" loads from stdin.
  -n --hostname=<HOSTNAME>     The hostname.
  -c --config=<CONFIG>         Filename containing connection configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
`
	parsedArgs, err := docopt.Parse(doc, args, true, "calicoctl", false, false)
	if err != nil {
		return err
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	cmd := delete{skipIfNotExists: parsedArgs["--skip-not-exists"].(bool)}
	results := executeConfigCommand(parsedArgs, cmd)
	glog.V(2).Infof("results: %+v", results)

	if results.fileInvalid {
		fmt.Printf("Error processing input file: %v\n", results.err)
	} else if results.numHandled == 0 {
		if results.numResources == 0 {
			fmt.Printf("No resources specified in file\n")
		} else if results.numResources == 1 {
			fmt.Printf("Failed to delete '%s' resource: %v\n", results.singleKind, results.err)
		} else if results.singleKind != "" {
			fmt.Printf("Failed to delete any '%s' resources: %v\n", results.singleKind, results.err)
		} else {
			fmt.Printf("Failed to delete any resources: %v\n", results.err)
		}
	} else if results.err == nil {
		if results.singleKind != "" {
			fmt.Printf("Successfully deleted %d '%s' resource(s)\n", results.numHandled, results.singleKind)
		} else {
			fmt.Printf("Successfully deleted %d resource(s)\n", results.numHandled)
		}
	} else {
		fmt.Printf("Partial success: ")
		if results.singleKind != "" {
			fmt.Printf("deleted the first %d out of %d '%s' resources:\n",
				results.numHandled, results.numResources, results.singleKind)
		} else {
			fmt.Printf("deleted the first %d out of %d resources:\n",
				results.numHandled, results.numResources)
		}
		fmt.Printf("Hit error: %v\n", results.err)
	}

	return results.err
}

// commandInterface for delete command.
// Maps the generic resource types to the typed client interface.
type delete struct {
	skipIfNotExists bool
}

func (d delete) execute(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
	var err error
	switch r := resource.(type) {
	case api.HostEndpoint:
		err = client.HostEndpoints().Delete(r.Metadata)
	case api.Policy:
		err = client.Policies().Delete(r.Metadata)
	case api.Pool:
		err = client.Pools().Delete(r.Metadata)
	case api.Profile:
		err = client.Profiles().Delete(r.Metadata)
	case api.WorkloadEndpoint:
		err = client.WorkloadEndpoints().Delete(r.Metadata)
	default:
		panic(fmt.Errorf("Unhandled resource type: %v", resource))
	}

	if err == nil {
		return resource, nil
	}

	// Handle resource does not exist errors explicitly.
	switch err.(type) {
	case errors.ErrorResourceDoesNotExist:
		if d.skipIfNotExists {
			return resource, nil
		}
	}
	return nil, err
}
