// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

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
	networkingv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/resourceloader"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"

	cconversion "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/converters"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

func Convert(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> convert --filename=<FILENAME>
                [--output=<OUTPUT>] [--ignore-validation] [--allow-version-mismatch]

Examples:
  # Convert the contents of policy.yaml to a Calico v3 policy.
  <BINARY_NAME> convert -f ./policy.yaml -o yaml

  # Convert a policy based on the JSON passed into stdin.
  cat policy.json | <BINARY_NAME> convert -f -

Options:
  -h --help                     Show this screen.
  -f --filename=<FILENAME>      Filename to use to create the resource. If set to
                                "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>   Output format. One of: yaml or json.
                                [Default: yaml]
     --ignore-validation        Skip validation on the converted manifest.
     --allow-version-mismatch   Allow client and cluster versions mismatch.


Description:
  Convert config files from Calico v1 or Kubernetes to Calico v3 API versions. Both YAML and JSON formats are accepted.

  The default output will be printed to stdout in YAML format.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	// Note: Intentionally not check version mismatch for this command

	var rp common.ResourcePrinter
	output := parsedArgs["--output"].(string)
	// Only supported output formats are yaml (default) and json.
	switch output {
	case "yaml", "yml":
		rp = common.ResourcePrinterYAML{}
	case "json":
		rp = common.ResourcePrinterJSON{}
	default:
		return fmt.Errorf("unrecognized output format '%s'", output)
	}

	filename := argutils.ArgStringOrBlank(parsedArgs, "--filename")

	// Load the resource from file and convert to a slice
	// of resources for easier handling.
	convRes, err := resourceloader.CreateResourcesFromFile(filename)
	if err != nil {
		return fmt.Errorf("Failed to create resources from file: %w", err)
	}

	// Unpack list resources (if any) into the slice
	convRes, err = unpackResourceLists(convRes)
	if err != nil {
		return fmt.Errorf("Failed to unpack lists: %w", err)
	}

	var results []runtime.Object

	for _, convResource := range convRes {
		v3Resource, err := convertResource(convResource)
		if err != nil {
			return fmt.Errorf("Failed to convert resource: %w", err)
		}

		// Remove any extra metadata the object might have.
		rom := v3Resource.(v1.ObjectMetaAccessor).GetObjectMeta()
		rom.SetUID("")
		rom.SetResourceVersion("")
		rom.SetCreationTimestamp(v1.Time{})
		rom.SetDeletionTimestamp(nil)
		rom.SetDeletionGracePeriodSeconds(nil)

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

	if len(results) > 1 {
		results, err = createV1List(results)
		if err != nil {
			return fmt.Errorf("Failed to create v1.List: %w", err)
		}
	}

	err = rp.Print(nil, results)
	if err != nil {
		return fmt.Errorf("Failed to print results: %w", err)
	}

	return nil
}

// convertResource converts a k8s or a calico v1 resource into a calico v3 resource.
func convertResource(convResource unversioned.Resource) (converters.Resource, error) {
	var res converters.Resource

	if strings.EqualFold(convResource.GetTypeMetadata().APIVersion, resourceloader.VersionK8sNetworkingV1) {
		// Convert K8s resource to v3 (currently only NetworkPolicy is supported)
		var err error

		res, err = convertK8sResource(convResource)
		if err != nil {
			return nil, err
		}
	} else {
		// Get the type converter for the v1 resource.
		convRes, err := getTypeConverter(convResource.GetTypeMetadata().Kind)
		if err != nil {
			return nil, err
		}

		// Convert v1 API resource to v1 backend KVPair.
		kvp, err := convRes.APIV1ToBackendV1(convResource)
		if err != nil {
			return nil, err
		}

		// Convert v1 backend KVPair to v3 API resource.
		res, err = convRes.BackendV1ToAPIV3(kvp)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

// Convert K8s resource to v3 (currently only NetworkPolicy is supported)
func convertK8sResource(convResource unversioned.Resource) (converters.Resource, error) {
	var res converters.Resource

	k8sResKind := convResource.GetTypeMetadata().Kind

	switch strings.ToLower(k8sResKind) {
	case "networkpolicy":
		k8sNetworkPolicy, ok := convResource.(*resourceloader.K8sNetworkPolicy)
		if !ok {
			return nil, fmt.Errorf("failed to convert resource to K8sNetworkPolicy")
		}

		np := networkingv1.NetworkPolicy{
			TypeMeta:   k8sNetworkPolicy.TypeMeta,
			ObjectMeta: k8sNetworkPolicy.ObjectMeta,
			Spec:       k8sNetworkPolicy.Spec,
		}
		c := cconversion.NewConverter()

		kvp, err := c.K8sNetworkPolicyToCalico(&np)
		if err != nil {
			return nil, fmt.Errorf("failed to convert k8s resource: %w", err)
		}

		k8snp, ok := kvp.Value.(*apiv3.NetworkPolicy)
		if !ok {
			return nil, fmt.Errorf("failed to convert kvp to apiv3.NetworkPolicy")
		}

		// Trim K8sNetworkPolicyNamePrefix from the policy name (the K8sNetworkPolicyToCalico
		// function adds it for when it is used for coexisting calico/k8s policies).
		k8snp.Name = strings.TrimPrefix(k8snp.Name, cconversion.K8sNetworkPolicyNamePrefix)

		res = k8snp

	default:
		return nil, fmt.Errorf("conversion for the k8s resource type '%s' is not supported", k8sResKind)
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

func unpackResourceLists(convRes []unversioned.Resource) ([]unversioned.Resource, error) {
	var unpackedConvRes []unversioned.Resource
	for _, convResource := range convRes {
		if strings.EqualFold(convResource.GetTypeMetadata().Kind, resourceloader.KindK8sListV1) && strings.EqualFold(convResource.GetTypeMetadata().APIVersion, resourceloader.VersionK8sListV1) {
			k8sNPList, ok := convResource.(*resourceloader.K8sNetworkPolicyList)
			if !ok {
				return nil, fmt.Errorf("failed to convert resource to K8sNetworkPolicyList")
			}

			for _, item := range k8sNPList.Items {
				// Append the items from the list to unpackedConvRes
				i := item
				unpackedConvRes = append(unpackedConvRes, &i)
			}
		} else {
			unpackedConvRes = append(unpackedConvRes, convResource)
		}
	}

	return unpackedConvRes, nil
}

func createV1List(results []runtime.Object) ([]runtime.Object, error) {
	list := v1.List{
		TypeMeta: v1.TypeMeta{
			Kind:       resourceloader.KindK8sListV1,
			APIVersion: resourceloader.VersionK8sListV1,
		},
	}

	for _, item := range results {
		var rawExt runtime.RawExtension

		err := runtime.Convert_runtime_Object_To_runtime_RawExtension(&item, &rawExt, nil)
		if err != nil {
			return nil, fmt.Errorf("Failed to convert runtime.Object to runtime.RawExtension: %w", err)
		}

		list.Items = append(list.Items, rawExt)
	}

	var obj []runtime.Object
	obj = append(obj, &list)

	return obj, nil
}
