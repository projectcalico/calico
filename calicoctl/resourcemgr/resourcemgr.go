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
	"strings"

	"io/ioutil"
	"os"

	"github.com/projectcalico/libcalico-go/lib/api/unversioned"

	"bytes"

	log "github.com/Sirupsen/logrus"
	"github.com/ghodss/yaml"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/validator"
)

// The ResourceManager interface provides useful function for each resource type.  This includes:
//	-  Commands to assist with generation of table output format of resources
//	-  Commands to manage resource instances through an un-typed interface.
type ResourceManager interface {
	GetTableDefaultHeadings(wide bool) []string
	GetTableTemplate(columns []string) (string, error)
	Apply(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error)
	Create(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error)
	Update(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error)
	Delete(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error)
	List(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error)
}

type ResourceActionCommand func(*client.Client, unversioned.Resource) (unversioned.Resource, error)

// ResourceHelper encapsulates details about a specific version of a specific resource:
//
// 	-  The type of resource (Kind and Version).  This includes the list types (even
//	   though they are not strictly resources themselves).
// 	-  The concrete resource struct for this version
//	-  Template strings used to format output for each resource type.
//	-  Functions to handle resource management actions (apply, create, update, delete, list).
//         These functions are an untyped interface (generic Resource interfaces) that map through
//         to the Calicc clients typed interface.
type resourceHelper struct {
	typeMetadata      unversioned.TypeMetadata
	resourceType      reflect.Type
	tableHeadings     []string
	tableHeadingsWide []string
	headingsMap       map[string]string
	isList            bool
	apply             ResourceActionCommand
	create            ResourceActionCommand
	update            ResourceActionCommand
	delete            ResourceActionCommand
	list              ResourceActionCommand
}

func (r resourceHelper) String() string {
	return fmt.Sprintf("Resource(%s %s)", r.typeMetadata.Kind, r.typeMetadata.APIVersion)
}

// Store a resourceHelper for each resource unversioned.TypeMetadata.
var helpers map[unversioned.TypeMetadata]resourceHelper

func registerResource(res unversioned.Resource, resList unversioned.Resource,
	tableHeadings []string, tableHeadingsWide []string, headingsMap map[string]string,
	apply, create, update, delete, list ResourceActionCommand) {

	if helpers == nil {
		helpers = make(map[unversioned.TypeMetadata]resourceHelper)
	}

	tmd := res.GetTypeMetadata()
	rh := resourceHelper{
		typeMetadata:      tmd,
		resourceType:      reflect.ValueOf(res).Elem().Type(),
		tableHeadings:     tableHeadings,
		tableHeadingsWide: tableHeadingsWide,
		headingsMap:       headingsMap,
		isList:            false,
		apply:             apply,
		create:            create,
		update:            update,
		delete:            delete,
		list:              list,
	}
	helpers[tmd] = rh

	tmd = resList.GetTypeMetadata()
	rh = resourceHelper{
		typeMetadata:      tmd,
		resourceType:      reflect.ValueOf(resList).Elem().Type(),
		tableHeadings:     tableHeadings,
		tableHeadingsWide: tableHeadingsWide,
		headingsMap:       headingsMap,
		isList:            true,
	}
	helpers[tmd] = rh
}

// Create a new concrete resource structure based on the type.  If the type is
// a list, this creates a concrete Resource-List of the required type.
func newResource(tm unversioned.TypeMetadata) (unversioned.Resource, error) {
	rh, ok := helpers[tm]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Unknown resource type (%s) and/or version (%s)", tm.Kind, tm.APIVersion))
	}
	log.Infof("Found resource helper: %s", rh)

	// Create new resource and fill in the type metadata.
	new := reflect.New(rh.resourceType)
	elem := new.Elem()
	elem.FieldByName("Kind").SetString(rh.typeMetadata.Kind)
	elem.FieldByName("APIVersion").SetString(rh.typeMetadata.APIVersion)

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

	if err = yaml.Unmarshal(b, unpacked); err != nil {
		return nil, err
	}

	log.Infof("Type of unpacked data: %v", reflect.TypeOf(unpacked))
	if err = validator.Validate(unpacked); err != nil {
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

// Implement the ResourceManager interface on the resourceHelper struct.

// GetTableDefaultHeadings returns the default headings to use in the ps-style get output
// for the resource.  Wide indicates whether the wide (true) or concise (false) column set is
// required.
func (rh resourceHelper) GetTableDefaultHeadings(wide bool) []string {
	if wide {
		return rh.tableHeadingsWide
	} else {
		return rh.tableHeadings
	}
}

// GetTableTemplate constructs the go-lang template string from the supplied set of headings.
// The template separates columns using tabs so that a tabwriter can be used to pretty-print
// the table.
func (rh resourceHelper) GetTableTemplate(headings []string) (string, error) {
	// Write the headings line.
	buf := new(bytes.Buffer)
	for _, heading := range headings {
		buf.WriteString(heading)
		buf.WriteByte('\t')
	}
	buf.WriteByte('\n')

	// If this is a list type, we need to iterate over the list items.
	if rh.isList {
		buf.WriteString("{{range .Items}}")
	}

	// For each column, add the go-template snippet for the corresponding field value.
	for _, heading := range headings {
		value, ok := rh.headingsMap[heading]
		if !ok {
			headings := make([]string, 0, len(rh.headingsMap))
			for heading := range rh.headingsMap {
				headings = append(headings, heading)
			}
			return "", fmt.Errorf("Unknown heading %s, valid values are: %s",
				heading,
				strings.Join(headings, ", "))
		}
		buf.WriteString(value)
		buf.WriteByte('\t')
	}
	buf.WriteByte('\n')

	// If this is a list, close off the range.
	if rh.isList {
		buf.WriteString("{{end}}")
	}

	return buf.String(), nil
}

// Apply is an un-typed method to apply (create or update) a resource.  This calls directly
// through to the resource helper specific Apply method which will map the untyped call to
// the typed interface on the client.
func (rh resourceHelper) Apply(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
	return rh.apply(client, resource)
}

// Create is an un-typed method to create a new resource.  This calls directly
// through to the resource helper specific Create method which will map the untyped call to
// the typed interface on the client.
func (rh resourceHelper) Create(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
	return rh.create(client, resource)
}

// Update is an un-typed method to update an existing resource.  This calls directly
// through to the resource helper specific Update method which will map the untyped call to
// the typed interface on the client.
func (rh resourceHelper) Update(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
	return rh.update(client, resource)
}

// Delete is an un-typed method to delete an existing resource.  This calls directly
// through to the resource helper specific Delete method which will map the untyped call to
// the typed interface on the client.
func (rh resourceHelper) Delete(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
	return rh.delete(client, resource)
}

// List is an un-typed method to list existing resources.  This calls directly
// through to the resource helper specific List method which will map the untyped call to
// the typed interface on the client.
func (rh resourceHelper) List(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
	return rh.list(client, resource)
}

// Return the Resource Manager for a particular resource type.
func GetResourceManager(resource unversioned.Resource) ResourceManager {
	return helpers[resource.GetTypeMetadata()]
}
