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

package resourceloader

import (
	"fmt"
	"io"
	"os"
	"reflect"

	log "github.com/sirupsen/logrus"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/projectcalico/go-yaml-wrapper"

	yamlsep "github.com/projectcalico/calico/calicoctl/calicoctl/util/yaml"
	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	v1validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v1"
)

var KindK8sListV1 = "List"
var VersionK8sListV1 = "v1"
var VersionK8sNetworkingV1 = "networking.k8s.io/v1"

// Store a resourceHelper for each resource unversioned.TypeMetadata.
var resourceToType map[unversioned.TypeMetadata]reflect.Type

func init() {
	resourceToType = make(map[unversioned.TypeMetadata]reflect.Type)
	populateResourceTypes()
}

// populateResourceTypes register all the V1 resource types in the resourceToType map.
func populateResourceTypes() {
	resTypes := []unversioned.Resource{
		apiv1.NewBGPPeer(),
		apiv1.NewIPPool(),
		apiv1.NewHostEndpoint(),
		apiv1.NewNode(),
		apiv1.NewPolicy(),
		apiv1.NewProfile(),
		apiv1.NewWorkloadEndpoint(),
		NewK8sNetworkPolicy(),
		NewK8sNetworkPolicyList(),
	}

	for _, rt := range resTypes {
		resourceToType[rt.GetTypeMetadata()] = reflect.ValueOf(rt).Elem().Type()
	}
}

// Create a new concrete resource structure based on the type.  If the type is
// a list, this creates a concrete Resource-List of the required type.
func newResource(tm unversioned.TypeMetadata) (unversioned.Resource, error) {
	rh, ok := resourceToType[tm]
	if !ok {
		return nil, fmt.Errorf("Unknown resource type (%s) and/or version (%s)", tm.Kind, tm.APIVersion)
	}
	log.Debugf("Found resource helper: %s", rh)

	// Create new resource and fill in the type metadata.
	new := reflect.New(rh)
	elem := new.Elem()
	elem.FieldByName("Kind").SetString(tm.GetTypeMetadata().Kind)
	elem.FieldByName("APIVersion").SetString(tm.GetTypeMetadata().APIVersion)

	return new.Interface().(unversioned.Resource), nil
}

// Create the resource from the specified byte array encapsulating the resource.
// -  The byte array may be JSON or YAML encoding of either a single resource or list of
//    resources as defined by the API objects in /api.
//
// The returned Resource will either be a single resource document or a List of documents.
// If the file does not contain any valid Resources this function returns an error.
func createResourcesFromBytes(b []byte) ([]unversioned.Resource, error) {
	// Start by unmarshalling the bytes into a TypeMetadata structure - this will ignore
	// other fields.
	var err error
	tm := unversioned.TypeMetadata{}
	tms := []unversioned.TypeMetadata{}
	if err = yaml.Unmarshal(b, &tm); err == nil {
		// We processed a metadata, so create a concrete resource struct to unpack
		// into.
		return unmarshalResource(tm, b)
	} else if err = yaml.Unmarshal(b, &tms); err == nil {
		// We processed a slice of metadata's, create a list of concrete resource
		// structs to unpack into.
		return unmarshalSliceOfResources(tms, b)
	} else {
		// Failed to parse a single resource or list of resources.
		return nil, err
	}
}

// Unmarshal a bytearray containing a single resource of the specified type into
// a concrete structure for that resource type.
//
// Return as a slice of Resource interfaces, containing a single element that is
// the unmarshalled resource.
func unmarshalResource(tm unversioned.TypeMetadata, b []byte) ([]unversioned.Resource, error) {
	log.Infof("Processing type %s", tm.Kind)
	unpacked, err := newResource(tm)
	if err != nil {
		return nil, err
	}

	if err = yaml.UnmarshalStrict(b, unpacked); err != nil {
		return nil, err
	}

	log.Infof("Type of unpacked data: %v", reflect.TypeOf(unpacked))
	if err = v1validator.Validate(unpacked); err != nil {
		return nil, err
	}

	log.Infof("Unpacked: %+v", unpacked)

	return []unversioned.Resource{unpacked}, nil
}

// Unmarshal a bytearray containing a list of resources of the specified types into
// a slice of concrete structures for those resource types.
//
// Return as a slice of Resource interfaces, containing an element that is each of
// the unmarshalled resources.
func unmarshalSliceOfResources(tml []unversioned.TypeMetadata, b []byte) ([]unversioned.Resource, error) {
	log.Infof("Processing list of resources")
	unpacked := make([]unversioned.Resource, len(tml))
	for i, tm := range tml {
		log.Infof("  - processing type %s", tm.Kind)
		r, err := newResource(tm)
		if err != nil {
			return nil, err
		}
		unpacked[i] = r
	}

	if err := yaml.UnmarshalStrict(b, &unpacked); err != nil {
		return nil, err
	}

	// Validate the data in the structures.  The v1validator does not handle slices, so
	// validate each resource separately.
	for _, r := range unpacked {
		if err := v1validator.Validate(r); err != nil {
			return nil, err
		}
	}

	log.Infof("Unpacked: %+v", unpacked)

	return unpacked, nil
}

// Create the Resource from the specified file f.
// 	-  The file format may be JSON or YAML encoding of either a single resource or list of
// 	   resources as defined by the API objects in /api.
// 	-  A filename of "-" means "Read from stdin".
//
// The returned Resource will either be a single Resource or a List containing zero or more
// Resources.  If the file does not contain any valid Resources this function returns an error.
func CreateResourcesFromFile(f string) ([]unversioned.Resource, error) {
	// Load the bytes from file or from stdin.
	var reader io.Reader
	var err error
	if f == "-" {
		reader = os.Stdin
	} else {
		reader, err = os.Open(f)
	}
	if err != nil {
		return nil, err
	}

	var resources []unversioned.Resource
	separator := yamlsep.NewYAMLDocumentSeparator(reader)
	for {
		b, err := separator.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		r, err := createResourcesFromBytes(b)
		if err != nil {
			return nil, err
		}

		resources = append(resources, r...)
	}

	return resources, nil
}

// Kubernetes NetworkPolicy helper struct used for conversion from
// Kubernetes API to Calico v3 API
type K8sNetworkPolicy struct {
	unversioned.TypeMetadata
	networkingv1.NetworkPolicy
}

func NewK8sNetworkPolicy() *K8sNetworkPolicy {
	return &K8sNetworkPolicy{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       "NetworkPolicy",
			APIVersion: VersionK8sNetworkingV1,
		},
	}
}

type K8sListMetadata struct {
	ResourceVersion string `json:"resourceVersion"`
	SelfLink        string `json:"selfLink"`
}

// K8sNetworkPolicyList contains a list of resources.
type K8sNetworkPolicyList struct {
	unversioned.TypeMetadata
	Metadata K8sListMetadata    `json:"metadata"`
	Items    []K8sNetworkPolicy `json:"items" validate:"dive"`
}

// NewK8sNetworkPolicyList creates a new (zeroed) K8sNetworkPolicyList struct with the
// TypeMetadata initialised to the current version.
func NewK8sNetworkPolicyList() *K8sNetworkPolicyList {
	return &K8sNetworkPolicyList{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       KindK8sListV1,
			APIVersion: VersionK8sListV1,
		},
	}
}
