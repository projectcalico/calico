// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calicoctl/calicoctl/commands/v1resourceloader"
	"github.com/projectcalico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/libcalico-go/lib/upgrade/converters"
	validator "github.com/projectcalico/libcalico-go/lib/validator/v3"
)

func Convert(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl convert --filename=<FILENAME>
                [--output=<OUTPUT>] [--ignore-validation]

Examples:
  # Convert the contents of policy.yaml to v3 policy.
  calicoctl convert -f ./policy.yaml -o yaml

  # Convert a policy based on the JSON passed into stdin.
  cat policy.json | calicoctl convert -f -

Options:
  -h --help                     Show this screen.
  -f --filename=<FILENAME>      Filename to use to create the resource. If set to
                                "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>   Output format. One of: yaml or json.
                                [Default: yaml]
  --ignore-validation           Skip validation on the converted manifest.


Description:
  Convert config files from Calico v1 to v3 API versions. Both YAML and JSON formats are accepted.

  The default output will be printed to stdout in YAML format.
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	var rp resourcePrinter
	output := parsedArgs["--output"].(string)
	// Only supported output formats are yaml (default) and json.
	switch output {
	case "yaml", "yml":
		rp = resourcePrinterYAML{}
	case "json":
		rp = resourcePrinterJSON{}
	default:
		return fmt.Errorf("unrecognized output format '%s'", output)
	}

	filename := argutils.ArgStringOrBlank(parsedArgs, "--filename")

	// Load the V1 resource from file and convert to a slice
	// of resources for easier handling.
	resV1, err := v1resourceloader.CreateResourcesFromFile(filename)
	if err != nil {
		return fmt.Errorf("Failed to execute command: %v", err)
	}

	var results []runtime.Object
	for _, v1Resource := range resV1 {
		v3Resource, err := convertResource(v1Resource)
		if err != nil {
			return fmt.Errorf("Failed to execute command: %v", err)
		}

		// Remove any extra metadata the object might have.
		rom := v3Resource.(v1.ObjectMetaAccessor).GetObjectMeta()
		rom.SetNamespace("")
		rom.SetUID("")
		rom.SetResourceVersion("")
		rom.SetCreationTimestamp(v1.Time{})
		rom.SetDeletionTimestamp(nil)
		rom.SetDeletionGracePeriodSeconds(nil)
		rom.SetClusterName("")

		ignoreValidation := argutils.ArgBoolOrFalse(parsedArgs, "--ignore-validation")
		if !ignoreValidation {
			if err := validator.Validate(v3Resource); err != nil {
				return fmt.Errorf("Converted manifest resource(s) failed validation: %s"+
					"Re-run the command with '--ignore-validation' flag to see the converted output.\n", err)
			}
		}

		results = append(results, v3Resource)
	}

	log.Infof("results: %+v", results)

	err = rp.print(nil, results)
	if err != nil {
		return fmt.Errorf("Failed to execute command: %v", err)
	}

	return nil
}

// convertResource converts v1 resource into a v3 resource.
func convertResource(v1resource unversioned.Resource) (converters.Resource, error) {
	// Get the type converter for the v1 resource.
	convRes, err := getTypeConverter(v1resource.GetTypeMetadata().Kind)
	if err != nil {
		return nil, err
	}

	// Convert v1 API resource to v1 backend KVPair.
	kvp, err := convRes.APIV1ToBackendV1(v1resource)
	if err != nil {
		return nil, err
	}

	// Convert v1 backend KVPair to v3 API resource.
	res, err := convRes.BackendV1ToAPIV3(kvp)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// getTypeConverter returns a type specific converter for a given v1 resource.
func getTypeConverter(resKind string) (converters.Converter, error) {
	switch strings.ToLower(resKind) {
	case "node":
		return converters.Node{}, nil
	case "hostendpoint":
		return converters.HostEndpoint{}, nil
	case "workloadendpoint":
		return converters.WorkloadEndpoint{}, nil
	case "profile":
		return converters.Profile{}, nil
	case "policy":
		return converters.Policy{}, nil
	case "ippool":
		return converters.IPPool{}, nil
	case "bgppeer":
		return converters.BGPPeer{}, nil

	default:
		return nil, fmt.Errorf("conversion for the resource type '%s' is not supported", resKind)
	}
}
