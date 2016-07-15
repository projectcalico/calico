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

package api

import (
	"errors"

	"fmt"
	"reflect"
	"strings"

	"io/ioutil"
	"os"

	. "github.com/tigera/libcalico-go/lib/api/unversioned"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/common"
)

var helpers map[TypeMetadata]resourceHelper
var helpersByType map[reflect.Type]resourceHelper

// Register all of the available resource types.
func init() {
	helpers = make(map[TypeMetadata]resourceHelper)
	helpersByType = make(map[reflect.Type]resourceHelper)

	registerHelper := func(t Resource, tl Resource) {
		// [smc] how about using an interface here rather than reflection?
		tmd := t.GetTypeMetadata()
		rh := resourceHelper{
			tmd,
			// [smc] I'm not up to speed on reflection, but can't you just use t here?
			reflect.ValueOf(t).Elem().Interface(),
			reflect.ValueOf(tl).Elem().Interface(),
		}
		helpers[tmd] = rh
		helpersByType[reflect.TypeOf(t)] = rh
	}

	// Register all API resources supported by the generic resource interface.
	registerHelper(NewPolicy(), NewPolicyList())
	registerHelper(NewProfile(), NewProfileList())
	registerHelper(NewHostEndpoint(), NewHostEndpointList())
}

// ResourceHelper encapsulates details about a specific version of a specific resource:
// -  The type of resource (Kind and Version)
// -  The concrete resource struct for this version
// -  The concrete resource list struct for this version
type resourceHelper struct {
	typeMetadata     TypeMetadata
	resourceType     interface{}
	resourceListType interface{}
}

// Create a new concrete resource structure based on the type.  If the type is
// a list, this creates a concrete Resource-List of the required type.
func NewResource(tm TypeMetadata) (interface{}, error) {
	isList := false
	itemType := tm

	// If this is a list type, then the item type is the resource that the list
	// contains rather than the list itself.
	if strings.HasSuffix(tm.Kind, "List") {
		itemType = TypeMetadata{
			Kind:       strings.TrimSuffix(tm.Kind, "List"),
			APIVersion: tm.APIVersion,
		}
		isList = true
	}

	rh, ok := helpers[itemType]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Unknown resource type (%s) and/or version (%s)", itemType.Kind, itemType.APIVersion))
	}
	glog.V(2).Infof("Found resource helper: %v\n", rh)
	glog.V(2).Infof("Type: %v\n", reflect.TypeOf(rh.resourceType))

	// Create new resource and fill in the type metadata.
	var new reflect.Value
	if isList {
		new = reflect.New(reflect.TypeOf(rh.resourceListType))
	} else {
		new = reflect.New(reflect.TypeOf(rh.resourceType))
	}
	elem := new.Elem()
	elem.FieldByName("Kind").SetString(tm.Kind)
	elem.FieldByName("APIVersion").SetString(tm.APIVersion)

	return new.Interface(), nil
}

// Create a new concrete Resource from the type of resource class.  This correctly
// fills in the type Metadata.
func NewResourceFromType(t reflect.Type) (interface{}, error) {
	rh, ok := helpersByType[t]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Unknown resource type %v", t))
	}
	glog.V(2).Infof("Found resource helper: %v\n", rh)
	glog.V(2).Infof("Type: %v\n", reflect.TypeOf(rh.resourceType))

	// Create new resource and fill in the type metadata.
	new := reflect.New(reflect.TypeOf(rh.resourceListType)).Elem()
	new.FieldByName("Kind").SetString(rh.typeMetadata.Kind)
	new.FieldByName("APIVersion").SetString(rh.typeMetadata.APIVersion)

	return new.Interface(), nil
}

// Create a new concrete Resource List from the type of resource class.  This correctly
// fills in the type Metadata.
func NewResourceListFromType(t reflect.Type) (interface{}, error) {
	rh, ok := helpersByType[t]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Unknown resource type %v", t))
	}
	glog.V(2).Infof("Found resource helper: %v\n", rh)
	glog.V(2).Infof("Type: %v\n", reflect.TypeOf(rh.resourceType))

	// Create new resource and fill in the type metadata.
	new := reflect.New(reflect.TypeOf(rh.resourceListType)).Elem()
	new.FieldByName("Kind").SetString(rh.typeMetadata.Kind)
	new.FieldByName("APIVersion").SetString(rh.typeMetadata.APIVersion)

	return new.Interface(), nil
}

// Create the Resource from the specified file f.
// -  The file format may be JSON or YAML encoding of either a single resource or list of
//    resources as defined by the API objects in /api.
// -  A filename of "-" means "Read from stdin".
//
// The returned Resource will either be a single Resource or a List containing zero or more
// Resources.  If the file does not contain any valid Resources this function returns an error.
func CreateResourceFromFile(f string) (interface{}, error) {

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

	return CreateResourceFromBytes(b)
}

// Create the resource from the specified byte array encapsulating the resource.
// -  The byte array may be JSON or YAML encoding of either a single resource or list of
//    resources as defined by the API objects in /api.
//
// The returned Resource will either be a single resource document or a List of documents.
// If the file does not contain any valid Resources this function returns an error.
func CreateResourceFromBytes(b []byte) (interface{}, error) {
	// Start by unmarshalling the bytes into a TypeMetadata structure - this will ignore
	// other fields.
	var err error
	tm := TypeMetadata{}
	tml := []TypeMetadata{}
	if err = yaml.Unmarshal(b, &tm); err == nil {
		// We processed a metadata, so create a concrete resource struct to unpack
		// into.
		return unmarshalResource(tm, b)
	} else if err = yaml.Unmarshal(b, &tml); err == nil {
		// We processed a list of metadata's, create a list of concrete resource
		// structs to unpack into.
		return unmarshalListOfResources(tml, b)
	} else {
		// Failed to parse a single resource or list of resources.
		return nil, err
	}
}

// Unmarshal a bytearray containing a single resource of the specified type into
// a concrete structure for that resource type.
func unmarshalResource(tm TypeMetadata, b []byte) (interface{}, error) {
	glog.V(2).Infof("Processing type %s\n", tm.Kind)
	unpacked, err := NewResource(tm)
	if err != nil {
		return nil, err
	}

	if err = yaml.Unmarshal(b, unpacked); err != nil {
		return nil, err
	}

	glog.V(2).Infof("Type of unpacked data: %v\n", reflect.TypeOf(unpacked))
	if err = common.Validate(unpacked); err != nil {
		return nil, err
	}

	glog.V(2).Infof("Unpacked: %v\n", unpacked)

	return unpacked, nil
}

// Unmarshal a bytearray containing a list of resources of the specified type into
// a list of concrete structures for that resource type.
func unmarshalListOfResources(tml []TypeMetadata, b []byte) (interface{}, error) {
	glog.V(2).Infof("Processing list of resources\n")
	unpacked := []interface{}{}
	for _, tm := range tml {
		glog.V(2).Infof("  - processing type %s\n", tm.Kind)
		r, err := NewResource(tm)
		if err != nil {
			return nil, err
		}
		unpacked = append(unpacked, r)
	}

	if err := yaml.Unmarshal(b, &unpacked); err != nil {
		return nil, err
	}

	// Validate the data in the structures.  The validator does not handle slices, so
	// validate each resource separately.
	for _, r := range unpacked {
		if err := common.Validate(r); err != nil {
			return nil, err
		}
	}

	glog.V(2).Infof("Unpacked: %v\n", unpacked)

	return unpacked, nil
}
