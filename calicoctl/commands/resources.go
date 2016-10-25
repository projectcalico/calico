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
	"reflect"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/ghodss/yaml"
	"github.com/projectcalico/calico-containers/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico-containers/calicoctl/resourcemgr"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/client"
	calicoErrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/scope"
)

type action int

const (
	actionApply action = iota
	actionCreate
	actionUpdate
	actionDelete
	actionList
)

// Convert loaded resources to a slice of resources for easier processing.
// The loaded resources may be a slice containing resources and resource lists, or
// may be a single resource or a single resource list.  This function handles the
// different possible options to convert to a single slice of resources.
func convertToSliceOfResources(loaded interface{}) []unversioned.Resource {
	r := []unversioned.Resource{}
	log.Infof("Converting resource to slice: %v", loaded)

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

	log.Infof("Returning slice: %v", r)
	return r
}

// getResourceFromArguments returns a resource instance from the command line arguments.
func getResourceFromArguments(args map[string]interface{}) (unversioned.Resource, error) {
	kind := args["<KIND>"].(string)
	name := argStringOrBlank(args, "<NAME>")
	node := argStringOrBlank(args, "--node")
	workload := argStringOrBlank(args, "--workload")
	orchestrator := argStringOrBlank(args, "--orchestrator")
	resScope := argStringOrBlank(args, "--scope")
	switch strings.ToLower(kind) {
	case "hostendpoints":
		fallthrough
	case "hostendpoint":
		h := api.NewHostEndpoint()
		h.Metadata.Name = name
		h.Metadata.Node = node
		return *h, nil
	case "workloadendpoints":
		fallthrough
	case "workloadendpoint":
		h := api.NewWorkloadEndpoint()
		h.Metadata.Name = name
		h.Metadata.Orchestrator = orchestrator
		h.Metadata.Workload = workload
		h.Metadata.Node = node
		return *h, nil
	case "profiles":
		fallthrough
	case "profile":
		p := api.NewProfile()
		p.Metadata.Name = name
		return *p, nil
	case "policies":
		fallthrough
	case "policy":
		p := api.NewPolicy()
		p.Metadata.Name = name
		return *p, nil
	case "pools":
		fallthrough
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
	case "bgppeers":
		fallthrough
	case "bgppeer":
		p := api.NewBGPPeer()
		if name != "" {
			err := p.Metadata.PeerIP.UnmarshalText([]byte(name))
			if err != nil {
				return nil, err
			}
		}
		p.Metadata.Node = node
		switch resScope {
		case "node":
			p.Metadata.Scope = scope.Node
		case "global":
			p.Metadata.Scope = scope.Global
		case "":
			p.Metadata.Scope = scope.Undefined
		default:
			return nil, fmt.Errorf("Unrecognized scope '%s', must be one of: global, node", resScope)
		}
		return *p, nil

	default:
		return nil, fmt.Errorf("Resource type '%s' is not supported", kind)
	}
}

// commandResults contains the results from executing a CLI command
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

// executeConfigCommand is main function called by all of the resource management commands
// in calicoctl (apply, create, replace, get and delete).  This provides common function
// for all these commands:
// 	-  Load resources from file (or if not specified determine the resource from
// 	   the command line options).
// 	-  Convert the loaded resources into a list of resources (easier to handle)
// 	-  Process each resource individually, fanning out to the appropriate methods on
//	   the client interface, collate results and exit on the first error.
func executeConfigCommand(args map[string]interface{}, action action) commandResults {
	var r interface{}
	var err error
	var resources []unversioned.Resource

	log.Info("Executing config command")

	if filename := args["--filename"]; filename != nil {
		// Filename is specified, load the resource from file and convert to a slice
		// of resources for easier handling.
		if r, err = resourcemgr.CreateResourcesFromFile(filename.(string)); err != nil {
			return commandResults{err: err, fileInvalid: true}
		}

		resources = convertToSliceOfResources(r)
	} else if r, err := getResourceFromArguments(args); err != nil {
		// Filename is not specific so extract the resource from the arguments.  This
		// is only useful for delete and get functions - but we don't need to check that
		// here since the command syntax requires a filename for the other resource
		// management commands.
		return commandResults{err: err}
	} else {
		// We extracted a single resource type with identifiers from the CLI, convert to
		// a list for simpler handling.
		resources = []unversioned.Resource{r}
	}

	if len(resources) == 0 {
		return commandResults{err: errors.New("no resources specified")}
	}

	if log.GetLevel() >= log.DebugLevel {
		log.Debugf("Resources: %v", resources)
		d, err := yaml.Marshal(resources)
		if err != nil {
			return commandResults{err: err}
		}
		log.Debugf("Data: %s", string(d))
	}

	// Load the client config and connect.
	cf := args["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		return commandResults{err: err}
	}
	log.Infof("Client: %v", client)

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
		r, err = executeResourceAction(args, client, r, action)
		if err != nil {
			results.err = err
			break
		}
		results.resources = append(results.resources, r)
		results.numHandled = results.numHandled + 1
	}

	return results
}

// argStringOrBlank returns the requested argument as a string, or as a blank
// string if the argument is not present.
func argStringOrBlank(args map[string]interface{}, argName string) string {
	if args[argName] != nil {
		return args[argName].(string)
	}
	return ""
}

// argBoolOrFalse returns the requested argument as a boolean, or as false
// if the argument is not present.
func argBoolOrFalse(args map[string]interface{}, argName string) bool {
	if args[argName] != nil {
		return args[argName].(bool)
	}
	return false
}

// execureResourceAction fans out the specific resource action to the appropriate method
// on the ResourceManager for the specific resource.
func executeResourceAction(args map[string]interface{}, client *client.Client, resource unversioned.Resource, action action) (unversioned.Resource, error) {
	rm := resourcemgr.GetResourceManager(resource)
	var err error
	var resourceOut unversioned.Resource

	switch action {
	case actionApply:
		resourceOut, err = rm.Apply(client, resource)
	case actionCreate:
		resourceOut, err = rm.Create(client, resource)
	case actionUpdate:
		resourceOut, err = rm.Update(client, resource)
	case actionDelete:
		resourceOut, err = rm.Delete(client, resource)
	case actionList:
		resourceOut, err = rm.List(client, resource)
	}

	// Skip over some errors depending on command line options.
	if err != nil {
		skip := false
		switch err.(type) {
		case calicoErrors.ErrorResourceAlreadyExists:
			skip = argBoolOrFalse(args, "--skip-exists")
		case calicoErrors.ErrorResourceDoesNotExist:
			skip = argBoolOrFalse(args, "--skip-not-exists")
		}
		if skip {
			resourceOut = resource
			err = nil
		}
	}

	return resourceOut, err
}
