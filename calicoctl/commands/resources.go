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
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/calicoctl/resourcemgr"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/api/unversioned"
	"github.com/tigera/libcalico-go/lib/client"
	"github.com/tigera/libcalico-go/lib/net"
)

// Convert loaded resources to a slice of resources for easier processing.
// The loaded resources may be a slice containing resources and resource lists, or
// may be a single resource or a single resource list.  This function handles the
// different possible options to convert to a single slice of resources.
func convertToSliceOfResources(loaded interface{}) []unversioned.Resource {
	r := []unversioned.Resource{}
	glog.V(2).Infof("Converting resource to slice: %v\n", loaded)

	switch reflect.TypeOf(loaded).Kind() {
	case reflect.Slice:
		// Recursively call this to add each resource in the supplied slice to
		// return slice.
		s := reflect.ValueOf(loaded)
		for i := 0; i < s.Len(); i++ {
			r = append(r, convertToSliceOfResources(s.Index(i).Interface())...)
		}
	case reflect.Struct:
		// This is a resource or resource list.  If a resource, add to our return
		// slice.  If a resource list, add each item to our return slice.
		lr := loaded.(unversioned.Resource)
		if strings.HasSuffix(lr.GetTypeMetadata().Kind, "List") {
			items := reflect.ValueOf(loaded).Elem().FieldByName("Items")
			for i := 0; i < items.Len(); i++ {
				r = append(r, items.Index(i).Interface().(unversioned.Resource))
			}
		} else {
			r = append(r, lr)
		}
	case reflect.Ptr:
		// This is a resource or resource list.  If a resource, add to our return
		// slice.  If a resource list, add each item to our return slice.
		lr := reflect.ValueOf(loaded).Elem().Interface().(unversioned.Resource)
		if strings.HasSuffix(lr.GetTypeMetadata().Kind, "List") {
			items := reflect.ValueOf(loaded).Elem().FieldByName("Items")
			for i := 0; i < items.Len(); i++ {
				r = append(r, items.Index(i).Interface().(unversioned.Resource))
			}
		} else {
			r = append(r, lr)
		}
	default:
		panic(errors.New(fmt.Sprintf("unhandled type %v converting to resource slice",
			reflect.TypeOf(loaded).Kind())))
	}

	glog.V(2).Infof("Returning slice: %v\n", r)
	return r
}

// Return a resource instance from the command line arguments.
func getResourceFromArguments(args map[string]interface{}) (unversioned.Resource, error) {
	kind := args["<KIND>"].(string)
	stringOrBlank := func(argName string) string {
		if args[argName] != nil {
			return args[argName].(string)
		}
		return ""
	}
	name := stringOrBlank("<NAME>")
	hostname := stringOrBlank("--hostname")
	switch kind {
	case "hostEndpoint":
		h := api.NewHostEndpoint()
		h.Metadata.Name = name
		h.Metadata.Hostname = hostname
		return *h, nil
	case "workloadEndpoint":
		h := api.NewWorkloadEndpoint() //TODO Need to add orchestrator ID and workload ID
		h.Metadata.Name = name
		h.Metadata.Hostname = hostname
		return *h, nil
	case "profile":
		p := api.NewProfile()
		p.Metadata.Name = name
		return *p, nil
	case "policy":
		p := api.NewPolicy()
		p.Metadata.Name = name
		return *p, nil
	case "pool":
		p := api.NewPool()
		if name != "" {
			_, cidr, err := net.ParseCIDR(name)
			if err != nil {
				return nil, err
			}
			p.Metadata.CIDR = *cidr
		}
		return *p, nil

	default:
		return nil, fmt.Errorf("Resource type '%s' is not unsupported", kind)
	}
}

// Interface to execute a command for a specific resource type.
type commandInterface interface {
	execute(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error)
}

// Results from executing a CLI command
type commandResults struct {
	// Whether the input file was invalid.
	fileInvalid bool

	// The number of resources that are being configured.
	numResources int

	// The number of resources that were actually configured.  This will
	// never be 0 without an associated error.
	numHandled int

	// The associated error.
	err error

	// The single type of resource that is being configured, or blank
	// if multiple resource types are being configured in a single shot.
	singleKind string

	// The results returned from each invocation
	resources []unversioned.Resource
}

// Common function for configuration commands apply, create, replace and delete.  All
// these commands:
// 	-  Load resources from file (or if not specified determine the resource from
// 	   the command line options).
// 	-  Convert the loaded resources into a list of resources (easier to handle)
// 	-  Process each resource individually, collate results and exit on the first error.
func executeConfigCommand(args map[string]interface{}, cmd commandInterface) commandResults {
	var r interface{}
	var err error
	var resources []unversioned.Resource

	glog.V(2).Info("Executing config command")

	if filename := args["--filename"]; filename != nil {
		// Filename is specified, load the resource from file and convert to a slice
		// of resources for easier handling.
		if r, err = resourcemgr.CreateResourcesFromFile(filename.(string)); err != nil {
			return commandResults{err: err, fileInvalid: true}
		}

		resources = convertToSliceOfResources(r)
	} else if r, err := getResourceFromArguments(args); err != nil {
		return commandResults{err: err, fileInvalid: true}
	} else {
		// We extracted a single resource type with identifiers from the CLI, convert to
		// a list for simpler handling.
		resources = []unversioned.Resource{r}
	}

	if len(resources) == 0 {
		return commandResults{err: errors.New("no resources specified")}
	}

	if glog.V(2) {
		glog.Infof("Resources: %v\n", resources)
		d, err := yaml.Marshal(resources)
		if err != nil {
			return commandResults{err: err}
		}
		glog.Infof("Data: %s\n", string(d))
	}

	// Load the client config and connect.
	cf := args["--config"].(string)
	client, err := newClient(cf)
	if err != nil {
		return commandResults{err: err}
	}
	glog.V(2).Infof("Client: %v\n", client)

	// Initialise the command results with the number of resources and the name of the
	// kind of resource (if only dealing with a single resource).
	var results commandResults
	var kind string
	count := make(map[string]int)
	for _, r := range resources {
		kind = r.GetTypeMetadata().Kind
		count[kind] = count[kind] + 1
		results.numResources = results.numResources + 1
	}
	if len(count) == 1 {
		results.singleKind = kind
	}

	// Now execute the command on each resource in order, exiting as soon as we hit an
	// error.
	for _, r := range resources {
		r, err = cmd.execute(client, r)
		if err != nil {
			results.err = err
			break
		}
		results.resources = append(results.resources, r)
		results.numHandled = results.numHandled + 1
	}

	return results
}
