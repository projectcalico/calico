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
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/client"

	"fmt"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/api/unversioned"
)

func Get(args []string) error {
	doc := EtcdIntro + `Display one or many resources identified by file, stdin or resource type and name.

Possible resource types include: policy

By specifying the output as 'template' and providing a Go template as the value
of the --template flag, you can filter the attributes of the fetched resource(s).

Usage:
  calicoctl get ([--hostname=<HOSTNAME>] (<KIND> [<NAME>]) | --filename=<FILENAME>) [--output=<OUTPUT>] [--config=<CONFIG>]

Examples:
  # List all policy in default output format.
  calicoctl get policy

  # List a specific policy in YAML format
  calicoctl get -o yaml policy my-policy-1

Options:
  -f --filename=<FILENAME>     Filename to use to get the resource.  If set to "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>  Output format.  One of: yaml, json.  [Default: yaml]
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

	cmd := get{}
	results := executeConfigCommand(parsedArgs, cmd)
	glog.V(2).Infof("results: %v", results)

	if results.err != nil {
		fmt.Printf("Error getting resources: %v\n", results.err)
		return err
	}

	// TODO Handle better - results should be groups as per input file
	// For simplicity convert the returned list of resources to expand any lists
	resources := convertToSliceOfResources(results.resources)

	if output, err := yaml.Marshal(resources); err != nil {
		fmt.Printf("Error outputing data: %v", err)
	} else {
		fmt.Printf("%s", string(output))
	}

	return nil
}

// commandInterface for replace command.
// Maps the generic resource types to the typed client interface.
type get struct {
}

func (g get) execute(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
	var err error
	switch r := resource.(type) {
	case api.HostEndpoint:
		resource, err = client.HostEndpoints().List(r.Metadata)
	case api.Policy:
		resource, err = client.Policies().List(r.Metadata)
	case api.Profile:
		resource, err = client.Profiles().List(r.Metadata)
	default:
		panic(fmt.Errorf("Unhandled resource type: %v", resource))
	}

	return resource, err
}
