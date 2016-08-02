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

package resourcemgr

import (
	"errors"

	"fmt"
	"reflect"

	"io/ioutil"
	"os"

	"github.com/tigera/libcalico-go/lib/api"
	. "github.com/tigera/libcalico-go/lib/api/unversioned"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/validator"
	"github.com/tigera/libcalico-go/calicoctl/resourcemgr"
)

// ResourceHelper encapsulates details about a specific version of a specific resource:
//
// 	-  The type of resource (Kind and Version).  This includes the list types (even
//	   though they are not strictly resources themselves).
// 	-  The concrete resource struct for this version
type resourceHelper struct {
	typeMetadata TypeMetadata
	resourceType reflect.Type
}

func (r resourceHelper) String() string {
	return fmt.Sprintf("Resource %s, version %s", r.typeMetadata.Kind, r.typeMetadata.APIVersion)
}

// Store a resourceHelper for each resource TypeMetadata.
var helpers map[TypeMetadata]resourceHelper

// Register all of the available resource types, this includes resource lists as well.
func init() {
	helpers = make(map[TypeMetadata]resourceHelper)

	registerHelper := func(t Resource) {
		tmd := t.GetTypeMetadata()
		rh := resourceHelper{
			tmd,
			reflect.ValueOf(t).Elem().Type(),
		}
		helpers[tmd] = rh
	}

	// Register all API resources supported by the generic resource interface.
	registerHelper(api.NewPolicy())
	registerHelper(api.NewPolicyList())
	registerHelper(api.NewPool())
	registerHelper(api.NewPoolList())
	registerHelper(api.NewProfile())
	registerHelper(api.NewProfileList())
	registerHelper(api.NewHostEndpoint())
	registerHelper(api.NewHostEndpointList())
	registerHelper(api.NewWorkloadEndpoint())
	registerHelper(api.NewWorkloadEndpointList())
}

// Create a new concrete resource structure based on the type.  If the type is
// a list, this creates a concrete Resource-List of the required type.
func newResource(tm TypeMetadata) (Resource, error) {
	rh, ok := helpers[tm]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Unknown resource type (%s) and/or version (%s)", tm.Kind, tm.APIVersion))
	}
	glog.V(2).Infof("Found resource helper: %s\n", rh)

	// Create new resource and fill in the type metadata.
	new := reflect.New(rh.resourceType)
	elem := new.Elem()
	elem.FieldByName("Kind").SetString(rh.typeMetadata.Kind)
	elem.FieldByName("APIVersion").SetString(rh.typeMetadata.APIVersion)

	return new.Interface().(Resource), nil
}

// Create the resource from the specified byte array encapsulating the resource.
// -  The byte array may be JSON or YAML encoding of either a single resource or list of
//    resources as defined by the API objects in /api.
//
// The returned Resource will either be a single resource document or a List of documents.
// If the file does not contain any valid Resources this function returns an error.
func createResourcesFromBytes(b []byte) ([]Resource, error) {
	// Start by unmarshalling the bytes into a TypeMetadata structure - this will ignore
	// other fields.
	var err error
	tm := TypeMetadata{}
	tms := []TypeMetadata{}
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
func unmarshalResource(tm TypeMetadata, b []byte) ([]Resource, error) {
	glog.V(2).Infof("Processing type %s\n", tm.Kind)
	unpacked, err := newResource(tm)
	if err != nil {
		return nil, err
	}

	if err = yaml.Unmarshal(b, unpacked); err != nil {
		return nil, err
	}

	glog.V(2).Infof("Type of unpacked data: %v\n", reflect.TypeOf(unpacked))
	if err = validator.Validate(unpacked); err != nil {
		return nil, err
	}

	glog.V(2).Infof("Unpacked: %+v\n", unpacked)

	return []Resource{unpacked}, nil
}

// Unmarshal a bytearray containing a list of resources of the specified types into
// a slice of concrete structures for those resource types.
//
// Return as a slice of Resource interfaces, containing an element that is each of
// the unmarshalled resources.
func unmarshalSliceOfResources(tml []TypeMetadata, b []byte) ([]Resource, error) {
	glog.V(2).Infof("Processing list of resources\n")
	unpacked := make([]Resource, len(tml))
	for i, tm := range tml {
		glog.V(2).Infof("  - processing type %s\n", tm.Kind)
		r, err := newResource(tm)
		if err != nil {
			return nil, err
		}
		unpacked[i] = r
	}

	if err := yaml.Unmarshal(b, &unpacked); err != nil {
		return nil, err
	}

	// Validate the data in the structures.  The validator does not handle slices, so
	// validate each resource separately.
	for _, r := range unpacked {
		if err := validator.Validate(r); err != nil {
			return nil, err
		}
	}

	glog.V(2).Infof("Unpacked: %+v\n", unpacked)

	return unpacked, nil
}

// Create the Resource from the specified file f.
// 	-  The file format may be JSON or YAML encoding of either a single resource or list of
// 	   resources as defined by the API objects in /api.
// 	-  A filename of "-" means "Read from stdin".
//
// The returned Resource will either be a single Resource or a List containing zero or more
// Resources.  If the file does not contain any valid Resources this function returns an error.
func CreateResourcesFromFile(f string) ([]Resource, error) {

	// Load the bytes from file or from stdin.
	var b []byte
	var err error

	if f == "-" {
		b, err = ioutil.ReadAll(os.Stdin)
	} else {
		b, err = ioutil.ReadFile(f)
	}
	if err != nil {
		return nil, err
	}

	return createResourcesFromBytes(b)
}
