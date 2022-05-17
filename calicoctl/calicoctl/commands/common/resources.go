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

package common

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/go-yaml-wrapper"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/file"
	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	calicoErrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

type action int

const (
	ActionApply action = iota
	ActionCreate
	ActionUpdate
	ActionDelete
	ActionGetOrList
	ActionPatch
)

// Convert loaded resources to a slice of resources for easier processing.
// The loaded resources may be a slice containing resources and resource lists, or
// may be a single resource or a single resource list.  This function handles the
// different possible options to convert to a single slice of resources.
func convertToSliceOfResources(loaded interface{}) ([]resourcemgr.ResourceObject, error) {
	res := []resourcemgr.ResourceObject{}
	log.Infof("Converting resource to slice: %v", loaded)
	switch r := loaded.(type) {
	case []runtime.Object:
		for i := 0; i < len(r); i++ {
			r, err := convertToSliceOfResources(r[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r...)
		}

	case resourcemgr.ResourceObject:
		res = append(res, r)

	case resourcemgr.ResourceListObject:
		ret, err := meta.ExtractList(r)
		if err != nil {
			return nil, err
		}

		for _, v := range ret {
			res = append(res, v.(resourcemgr.ResourceObject))
		}
	}

	log.Infof("Returning slice: %v", res)
	return res, nil
}

// CommandResults contains the results from executing a CLI command
type CommandResults struct {
	// Whether the input file was invalid.
	FileInvalid bool

	// The number of resources that are being configured.
	NumResources int

	// The number of resources that were actually configured.  This will
	// never be 0 without an associated error.
	NumHandled int

	// The associated error.
	Err error

	// The single type of resource that is being configured, or blank
	// if multiple resource types are being configured in a single shot.
	SingleKind string

	// The results returned from each invocation
	Resources []runtime.Object

	// Errors associated with individual resources
	ResErrs []error

	// The Calico API client used for the requests (useful if required
	// again).
	Client client.Interface
}

type fileError struct {
	error
}

// ExecuteConfigCommand is main function called by all of the resource management commands
// in calicoctl (apply, create, replace, get, delete and patch).  This provides common function
// for all these commands:
// 	-  Load resources from file (or if not specified determine the resource from
// 	   the command line options).
// 	-  Convert the loaded resources into a list of resources (easier to handle)
// 	-  Process each resource individually, fanning out to the appropriate methods on
//	   the client interface, collate results and exit on the first error.
func ExecuteConfigCommand(args map[string]interface{}, action action) CommandResults {
	var resources []resourcemgr.ResourceObject

	singleKind := false

	log.Info("Executing config command")

	err := CheckVersionMismatch(args["--config"], args["--allow-version-mismatch"])
	if err != nil {
		return CommandResults{Err: err}
	}

	errorOnEmpty := !argutils.ArgBoolOrFalse(args, "--skip-empty")

	if filename := args["--filename"]; filename != nil {
		// Filename is specified.  Use the file iterator to handle the fact that this may be a directory rather than a
		// single file. For each file load the resources from the file and convert to a single slice of resources for
		// easier handling.
		err := file.Iter(args, func(modifiedArgs map[string]interface{}) error {
			modifiedFilename := modifiedArgs["--filename"].(string)

			r, err := resourcemgr.CreateResourcesFromFile(modifiedFilename)
			if err != nil {
				return fileError{err}
			}

			converted, err := convertToSliceOfResources(r)
			if err != nil {
				return fileError{err}
			}

			if len(converted) == 0 && errorOnEmpty {
				// We should fail on empty files.
				return fmt.Errorf("No resources specified in file %s", modifiedFilename)
			}

			resources = append(resources, converted...)
			return nil
		})
		if err != nil {
			_, ok := err.(fileError)
			return CommandResults{Err: err, FileInvalid: ok}
		}

		if len(resources) == 0 {
			if errorOnEmpty {
				// Empty files are handled above, so the only way to get here is if --filename pointed to a directory.
				// We can therefore tweak the error message slightly to be more specific.
				return CommandResults{
					Err: fmt.Errorf("No resources specified in directory %s", filename),
				}
			} else {
				// No data, but not an error case. Return an empty set of results.
				return CommandResults{}
			}
		}
	} else {
		// Filename is not specific so extract the resource from the arguments. This
		// is only useful for delete, get and patch functions - but we don't need to check that
		// here since the command syntax requires a filename for the other resource
		// management commands.
		var err error
		singleKind = true
		resources, err = resourcemgr.GetResourcesFromArgs(args)
		if err != nil {
			return CommandResults{Err: err}
		}

		if len(resources) == 0 {
			// No resources specified on non-file input is always an error.
			return CommandResults{
				Err: fmt.Errorf("No resources specified"),
			}
		}
	}

	if log.GetLevel() >= log.DebugLevel {
		for _, v := range resources {
			log.Debugf("Resource: %s", v.GetObjectKind().GroupVersionKind().String())
		}

		d, err := yaml.Marshal(resources)
		if err != nil {
			return CommandResults{Err: err}
		}
		log.Debugf("Data: %s", string(d))
	}

	// Load the client config and connect.
	cf := args["--config"].(string)
	cclient, err := clientmgr.NewClient(cf)
	if err != nil {
		fmt.Printf("Failed to create Calico API client: %s\n", err)
		os.Exit(1)
	}
	log.Infof("Client: %v", cclient)

	// Initialise the command results with the number of resources and the name of the
	// kind of resource (if only dealing with a single resource).
	results := CommandResults{Client: cclient}
	var kind string
	count := make(map[string]int)
	for _, r := range resources {
		kind = r.GetObjectKind().GroupVersionKind().Kind
		count[kind] = count[kind] + 1
		results.NumResources = results.NumResources + 1
	}
	if len(count) == 1 || singleKind {
		results.SingleKind = kind
	}

	// Now execute the command on each resource in order, exiting as soon as we hit an
	// error.
	export := argutils.ArgBoolOrFalse(args, "--export")
	nameSpecified := false
	emptyName := false
	switch a := args["<NAME>"].(type) {
	case string:
		nameSpecified = len(a) > 0
		_, ok := args["<NAME>"]
		emptyName = !ok || !nameSpecified
	case []string:
		nameSpecified = len(a) > 0
		for _, v := range a {
			if v == "" {
				emptyName = true
			}
		}
	}

	if emptyName {
		return CommandResults{Err: fmt.Errorf("resource name may not be empty")}
	}

	for _, r := range resources {
		res, err := ExecuteResourceAction(args, cclient, r, action)
		if err != nil {
			switch action {
			case ActionApply, ActionCreate, ActionDelete, ActionGetOrList:
				results.ResErrs = append(results.ResErrs, err)
				continue
			default:
				results.Err = err
			}
		}

		// Remove the cluster specific metadata if the "--export" flag is specified
		// Skip removing cluster specific metadata if this is is called as a "list"
		// operation (no specific name is specified).
		if export && nameSpecified {
			for i := range res {
				rom := res[i].(v1.ObjectMetaAccessor).GetObjectMeta()
				rom.SetNamespace("")
				rom.SetUID("")
				rom.SetResourceVersion("")
				rom.SetCreationTimestamp(v1.Time{})
				rom.SetDeletionTimestamp(nil)
				rom.SetDeletionGracePeriodSeconds(nil)
			}
		}

		results.Resources = append(results.Resources, res...)
		results.NumHandled = results.NumHandled + len(res)
	}

	return results
}

// ExecuteResourceAction fans out the specific resource action to the appropriate method
// on the ResourceManager for the specific resource.
func ExecuteResourceAction(args map[string]interface{}, client client.Interface, resource resourcemgr.ResourceObject, action action) ([]runtime.Object, error) {
	rm := resourcemgr.GetResourceManager(resource)

	err := handleNamespace(resource, rm, args)
	if err != nil {
		return nil, err
	}

	var resOut runtime.Object
	ctx := context.Background()

	switch action {
	case ActionApply:
		resOut, err = rm.Apply(ctx, client, resource)
	case ActionCreate:
		resOut, err = rm.Create(ctx, client, resource)
	case ActionUpdate:
		resOut, err = rm.Update(ctx, client, resource)
	case ActionDelete:
		resOut, err = rm.Delete(ctx, client, resource)
	case ActionGetOrList:
		resOut, err = rm.GetOrList(ctx, client, resource)
	case ActionPatch:
		patch := args["--patch"].(string)
		resOut, err = rm.Patch(ctx, client, resource, patch)
	}

	// Skip over some errors depending on command line options.
	if err != nil {
		skip := false
		switch err.(type) {
		case calicoErrors.ErrorResourceAlreadyExists:
			skip = argutils.ArgBoolOrFalse(args, "--skip-exists")
		case calicoErrors.ErrorResourceDoesNotExist:
			skip = argutils.ArgBoolOrFalse(args, "--skip-not-exists")
		}
		if skip {
			resOut = resource
			err = nil
		}
	}

	return []runtime.Object{resOut}, err
}

// handleNamespace fills in the namespace information in the resource (if required),
// and validates the namespace depending on whether or not a namespace should be
// provided based on the resource kind.
func handleNamespace(resource resourcemgr.ResourceObject, rm resourcemgr.ResourceManager, args map[string]interface{}) error {
	allNs := argutils.ArgBoolOrFalse(args, "--all-namespaces")
	cliNs := argutils.ArgStringOrBlank(args, "--namespace")
	resNs := resource.GetObjectMeta().GetNamespace()

	if rm.IsNamespaced() {
		switch {
		case allNs && cliNs != "":
			// Check if --namespace and --all-namespaces flags are used together.
			return fmt.Errorf("cannot use both --namespace and --all-namespaces flags at the same time")
		case resNs == "" && cliNs != "":
			// If resource doesn't have a namespace specified
			// but it's passed in through the -n flag then use that one.
			resource.GetObjectMeta().SetNamespace(cliNs)
		case resNs != "" && allNs:
			// If --all-namespaces is used then we must set namespace to "" so
			// list operation can list resources from all the namespaces.
			resource.GetObjectMeta().SetNamespace("")
		case resNs == "" && allNs:
			// no-op
		case resNs == "" && cliNs == "" && !allNs:
			// Set the namespace to "default" if not specified.
			resource.GetObjectMeta().SetNamespace("default")
		case resNs != "" && cliNs == "":
			// Use the namespace specified in the resource, which is already set.
		case resNs != cliNs:
			// If both resource and the CLI pass in the namespace but they don't match then return an error.
			return fmt.Errorf("resource namespace does not match client namespace. %s != %s", resNs, cliNs)
		}
	} else if resNs != "" {
		return fmt.Errorf("namespace should not be specified for a non-namespaced resource. %s is not a namespaced resource",
			resource.GetObjectKind().GroupVersionKind().Kind)
	} else if allNs || cliNs != "" {
		return fmt.Errorf("%s is not namespaced", resource.GetObjectKind().GroupVersionKind().Kind)
	}

	return nil
}
