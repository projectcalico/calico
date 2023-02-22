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

package resourcemgr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/strategicpatch"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	yaml "github.com/projectcalico/go-yaml-wrapper"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	yamlsep "github.com/projectcalico/calico/calicoctl/calicoctl/util/yaml"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// ResourceManager provides a useful function for each resource type.  This includes:
//   - Commands to assist with generation of table output format of resources
//   - Commands to manage resource instances through an un-typed interface.
type ResourceManager interface {
	GetTableDefaultHeadings(wide bool) []string
	GetTableTemplate(columns []string, printNamespace bool) (string, error)
	GetObjectType() reflect.Type
	IsNamespaced() bool
	Apply(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error)
	Create(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error)
	Update(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error)
	Delete(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error)
	GetOrList(ctx context.Context, client client.Interface, resource ResourceObject) (runtime.Object, error)
	Patch(ctx context.Context, client client.Interface, resource ResourceObject, patch string) (ResourceObject, error)
}

// ResourceObject is implemented by all Calico resources
type ResourceObject interface {
	runtime.Object
	v1.ObjectMetaAccessor
}

// ResourceListObject is implemented by all Calico resources lists
type ResourceListObject interface {
	runtime.Object
	v1.ListMetaAccessor
}

type ResourceActionCommand func(context.Context, client.Interface, ResourceObject) (ResourceObject, error)
type ResourceListActionCommand func(context.Context, client.Interface, ResourceObject) (ResourceListObject, error)

// ResourceHelper encapsulates details about a specific version of a specific resource:
//
//   - The type of resource (Kind and Version).  This includes the list types (even
//     though they are not strictly resources themselves).
//   - The concrete resource struct for this version
//   - Template strings used to format output for each resource type.
//   - Functions to handle resource management actions (apply, create, update, delete, list).
//     These functions are an untyped interface (generic Resource interfaces) that map through
//     to the Calico clients typed interface.
type resourceHelper struct {
	resource          runtime.Object
	listResource      ResourceListObject
	resourceType      reflect.Type
	tableHeadings     []string
	tableHeadingsWide []string
	headingsMap       map[string]string
	isList            bool
	isNamespaced      bool
	create            ResourceActionCommand
	update            ResourceActionCommand
	delete            ResourceActionCommand
	get               ResourceActionCommand
	list              ResourceListActionCommand
}

func (rh resourceHelper) String() string {
	if !rh.isList {
		return fmt.Sprintf("Resource(%s %s)", rh.resource.GetObjectKind(), rh.resource.GetObjectKind().GroupVersionKind())

	}
	return fmt.Sprintf("Resource(%s %s)", rh.listResource.GetObjectKind(), rh.listResource.GetListMeta().GetResourceVersion())
}

// Store a resourceHelper for each resource.
var helpers map[schema.GroupVersionKind]resourceHelper
var kindToRes = make(map[string]ResourceObject)

func registerResource(res ResourceObject, resList ResourceListObject, isNamespaced bool, names []string,
	tableHeadings []string, tableHeadingsWide []string, headingsMap map[string]string,
	create, update, delete, get ResourceActionCommand, list ResourceListActionCommand) {

	if helpers == nil {
		helpers = make(map[schema.GroupVersionKind]resourceHelper)
	}

	rh := resourceHelper{
		resource:          res,
		resourceType:      reflect.ValueOf(res).Elem().Type(),
		tableHeadings:     tableHeadings,
		tableHeadingsWide: tableHeadingsWide,
		headingsMap:       headingsMap,
		isList:            false,
		isNamespaced:      isNamespaced,
		create:            create,
		update:            update,
		delete:            delete,
		get:               get,
		list:              list,
	}
	helpers[res.GetObjectKind().GroupVersionKind()] = rh

	rh = resourceHelper{
		listResource:      resList,
		resourceType:      reflect.ValueOf(resList).Elem().Type(),
		tableHeadings:     tableHeadings,
		tableHeadingsWide: tableHeadingsWide,
		headingsMap:       headingsMap,
		isList:            true,
	}
	helpers[resList.GetObjectKind().GroupVersionKind()] = rh

	for _, v := range names {
		kindToRes[v] = res
	}
}

func (rh resourceHelper) GetObjectType() reflect.Type {
	return rh.resourceType
}

// Apply is an un-typed method to apply (create or update) a resource. This calls Create
// and if the resource already exists then we call the Update method.
func (rh resourceHelper) Apply(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
	// Block operations on ClusterInfo as calico/node is responsible for managing it.
	if _, ok := resource.(*api.ClusterInformation); ok {
		return nil, cerrors.ErrorOperationNotSupported{
			Operation:  "apply",
			Identifier: "ClusterInformation",
			Reason:     "resource is readonly",
		}
	}

	// Store the original ResourceVersion for the Update operation later.
	originalRV := resource.GetObjectMeta().GetResourceVersion()

	// Remove the resourceVersion, because Create call can't have
	// resourceVersion set and Update automatically gets and sets
	// the resourceVersion to the latest one from the datastore.
	resource.GetObjectMeta().SetResourceVersion("")

	// Try to create the resource first.
	ro, err := rh.Create(ctx, client, resource)

	// Fall back to an Update if the resource already exists, or the datastore does not support
	// create operations for that resource.
	switch err.(type) {
	case cerrors.ErrorResourceAlreadyExists, cerrors.ErrorOperationNotSupported:
		// Insert the original ResourceVersion back into the object before trying the Update.
		resource.GetObjectMeta().SetResourceVersion(originalRV)

		// Try updating if the resource already exists.
		return rh.Update(ctx, client, resource)
	}

	// For any other errors, return the error
	return ro, err
}

// Create is an un-typed method to create a new resource.  This calls directly
// through to the resource helper specific Create method which will map the untyped call to
// the typed interface on the client.
func (rh resourceHelper) Create(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
	resourceCopy := prepareMetadataForCreate(resource)
	return rh.create(ctx, client, resourceCopy)
}

// Update is an un-typed method to update an existing resource. This calls the resource
// specific Get method to get the resourceVersion, and then calls resource specific
// Update method with the resource with the updated resourceVersion, but if the resourceVersion is provided
// then we use that. We retry 5 times if there is an update conflict during the Update operation.
func (rh resourceHelper) Update(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
	var err error

	// Check to see if the resourceVersion is specified in the resource object.
	rv := resource.GetObjectMeta().GetResourceVersion()

	// Copy the resource to prevent modifying the input resource metadata.
	resource = resource.DeepCopyObject().(ResourceObject)

	// If the resourceVersion is specified then we use it to try and update the resource.
	// Do not attempt to retry if the resource version is specified.
	if rv != "" {
		// Clean out the resource version to always get the latest revision.
		resource.GetObjectMeta().SetResourceVersion("")
		// Validate the metadata is not changed for the the resource.
		ro, err := rh.get(ctx, client, resource)
		if err != nil {
			return ro, err
		}
		// Check that the resource version is the latest
		if rv != ro.GetObjectMeta().GetResourceVersion() {
			id := fmt.Sprintf("%s(%s)", ro.GetObjectKind().GroupVersionKind().GroupKind().Kind, ro.GetObjectMeta().GetName())
			if ro.GetObjectMeta().GetNamespace() != "" {
				id = fmt.Sprintf("%s(%s/%s)", ro.GetObjectKind().GroupVersionKind().GroupKind().Kind, ro.GetObjectMeta().GetNamespace(), ro.GetObjectMeta().GetName())
			}
			return ro, cerrors.ErrorResourceUpdateConflict{
				Err:        fmt.Errorf(fmt.Sprintf("Resource version '%s' is out of date (latest: %s). Update the resource YAML/JSON in order to make changes.", rv, ro.GetObjectMeta().GetResourceVersion())),
				Identifier: id,
			}
		}
		resource = mergeMetadataForUpdate(ro, resource)

		return rh.update(ctx, client, resource)
	}

	// If the resourceVersion is not specified then we do a Get to get
	// the latest resourceVersion and then do an Update with it.
	// We retry only if we get an update conflict.
	for i := 0; i < 5; i++ {
		// Get the resource to get the resourceVersion.
		ro, err := rh.get(ctx, client, resource)
		if err != nil {
			return ro, err
		}

		resource = mergeMetadataForUpdate(ro, resource)

		// Try to update with the resource with the updated resourceVersion.
		ru, err := rh.update(ctx, client, resource)
		if _, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
			// Wait for a second and try again if there was a conflict during the resource update.
			log.Infof("Error updating the resource %s: %s. Retrying.", resource.GetObjectMeta().GetName(), err)
			time.Sleep(1 * time.Second)
			continue
		}

		// For any other errors or nil error, return the result and error.
		return ru, err
	}

	return nil, fmt.Errorf("failed to update the resource: %s", err)
}

// Delete is an un-typed method to delete an existing resource.  This calls directly
// through to the resource helper specific Delete method which will map the untyped call to
// the typed interface on the client.
func (rh resourceHelper) Delete(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
	return rh.delete(ctx, client, resource)
}

// GetOrList is an un-typed method to get an existing resource. This calls directly
// through to the resource helper specific Get (if the resource name is set)
// or List (if the resource name is empty) method which will map the untyped call to
// the typed interface on the client.
func (rh resourceHelper) GetOrList(ctx context.Context, client client.Interface, resource ResourceObject) (runtime.Object, error) {
	if resource.GetObjectMeta().GetName() != "" {
		if resource.GetObjectMeta().GetNamespace() == "" && rh.isNamespaced {
			return nil, fmt.Errorf("cannot use --all-namespace flag for getting a single resource")
		}
		return rh.get(ctx, client, resource)
	}

	return rh.list(ctx, client, resource)
}

// Patch is an un-typed method to patch an existing resource.
// It currently take a partial JSON object and attempts to perform a strategic merge
// on the existing resource.
func (rh resourceHelper) Patch(ctx context.Context, client client.Interface, resource ResourceObject, patch string) (ResourceObject, error) {
	ro, err := rh.get(ctx, client, resource)
	if err != nil {
		return ro, err
	}

	resource = mergeMetadataForPatch(ro, resource)

	// Marshal original obj for comparison
	original, err := json.Marshal(ro)
	if err != nil {
		return resource, fmt.Errorf("marshalling original resource: %v", err)
	}

	// perform strategic merge
	patched, err := strategicpatch.StrategicMergePatch(original, []byte(patch), ro.DeepCopyObject())
	if err != nil {
		return resource, fmt.Errorf("permorming strategic merge patch: %v", err)
	}

	// convert patched data to resource
	resources, err := createResourcesFromBytes(patched)
	if err != nil {
		return resource, fmt.Errorf("creating resource from patched data: %v", err)
	}

	if len(resources) < 1 {
		return resource, fmt.Errorf("invalid number of patched resources: %v", len(resources))
	}

	resource = resources[0].(ResourceObject)

	resource, err = rh.update(ctx, client, resource)
	if err != nil {
		return resource, fmt.Errorf("updating existing resource: %v", err)
	}

	return resource, nil
}

// GetResourceManager returns the Resource Manager for a particular resource type.
func GetResourceManager(resource runtime.Object) ResourceManager {
	return helpers[resource.GetObjectKind().GroupVersionKind()]
}

// GetResourcesFromArgs gets resources from arguments.
// This function also inserts resource name, namespace if specified.
// Example "calicoctl get bgppeer peer123" will return
// a BGPPeer resource with name field populated to "peer123".
func GetResourcesFromArgs(args map[string]interface{}) ([]ResourceObject, error) {
	kind := args["<KIND>"].(string)
	argname := "<NAME>"

	var names []string

	switch args[argname].(type) {
	case string:
		name := argutils.ArgStringOrBlank(args, argname)
		names = append(names, name)
	case []string:
		names = argutils.ArgStringsOrBlank(args, argname)
	default:
		panic(fmt.Errorf("Wrong name format, unexpected type: %T", args[argname]))
	}

	namespace := argutils.ArgStringOrBlank(args, "--namespace")

	var ret []ResourceObject

	for _, name := range names {
		res, ok := kindToRes[strings.ToLower(kind)]
		if !ok {
			return nil, fmt.Errorf("resource type '%s' is not supported", kind)
		}
		res = res.DeepCopyObject().(ResourceObject)
		res.GetObjectMeta().SetName(name)

		// Set the namespace if the object kind is namespaced.
		if helpers[res.GetObjectKind().GroupVersionKind()].isNamespaced {
			res.GetObjectMeta().SetNamespace(namespace)
		}

		ret = append(ret, res)
	}

	return ret, nil
}

// Check if the resource kind is namespaced.
func (rh resourceHelper) IsNamespaced() bool {
	return rh.isNamespaced
}

// Create a new concrete resource structure based on the type.  If the type is
// a list, this creates a concrete Resource-List of the required type.
func newResource(tm schema.GroupVersionKind) (runtime.Object, error) {
	rh, ok := helpers[tm]
	if !ok {
		return nil, fmt.Errorf("Unknown resource type (%s) and/or version (%s)", tm.Kind, tm.GroupVersion().String())
	}
	log.Infof("Found resource helper: %s", rh)

	// Create new resource and fill in the type metadata.
	n := reflect.New(rh.resourceType)
	elem := n.Elem()
	elem.FieldByName("Kind").SetString(tm.Kind)
	elem.FieldByName("APIVersion").SetString(tm.GroupVersion().String())

	_, ok = n.Interface().(ResourceObject)
	if ok {
		return n.Interface().(ResourceObject), nil
	}
	return n.Interface().(ResourceListObject), nil
}

// Create the resource from the specified byte array encapsulating the resource.
//   - The byte array may be JSON or YAML encoding of either a single resource or list of
//     resources as defined by the API objects in /api.
//
// The returned Resource will either be a single resource document or a List of documents.
// If the file does not contain any valid Resources this function returns an error.
func createResourcesFromBytes(b []byte) ([]runtime.Object, error) {
	// Start by unmarshalling the bytes into a TypeMetadata structure - this will ignore
	// other fields.
	var err error
	tm := unstructured.Unstructured{}
	tms := []unstructured.Unstructured{}
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
func unmarshalResource(tm unstructured.Unstructured, b []byte) ([]runtime.Object, error) {
	log.Infof("Processing type %s", tm.GetObjectKind())
	unpacked, err := newResource(tm.GroupVersionKind())
	if err != nil {
		return nil, err
	}

	if err = yaml.UnmarshalStrict(b, unpacked); err != nil {
		return nil, err
	}

	log.Infof("Type of unpacked data: %v. Unpacked %+v", reflect.TypeOf(unpacked), unpacked)

	return []runtime.Object{unpacked}, nil
}

// Unmarshal a bytearray containing a list of resources of the specified types into
// a slice of concrete structures for those resource types.
//
// Return as a slice of Resource interfaces, containing an element that is each of
// the unmarshalled resources.
func unmarshalSliceOfResources(tml []unstructured.Unstructured, b []byte) ([]runtime.Object, error) {
	log.Infof("Processing list of resources")
	unpacked := make([]runtime.Object, len(tml))
	for i, tm := range tml {
		log.Infof("  - processing type %s", tm.GetObjectKind())
		r, err := newResource(tm.GroupVersionKind())
		if err != nil {
			return nil, err
		}
		unpacked[i] = r
	}

	if err := yaml.UnmarshalStrict(b, &unpacked); err != nil {
		return nil, err
	}

	log.Infof("Unpacked: %+v", unpacked)

	return unpacked, nil
}

// CreateResourcesFromFile creates the Resource from the specified file f.
//   - The file format may be JSON or YAML encoding of either a single resource or list of
//     resources as defined by the API objects in /api.
//   - A filename of "-" means "Read from stdin".
//
// The returned Resource will either be a single Resource or a List containing zero or more
// Resources.  If the file does not contain any valid Resources this function returns an error.
func CreateResourcesFromFile(f string) ([]runtime.Object, error) {
	// Load the bytes from file or from stdin.
	logCxt := log.WithField("source", f)
	var reader io.Reader
	var err error
	if f == "-" {
		reader = os.Stdin
	} else {
		reader, err = os.Open(f)
		if err != nil {
			logCxt.WithError(err).Error("Failed to open file")
			return nil, err
		}
	}

	logCxt.Debug("Creating document separator")
	var resources []runtime.Object
	separator := yamlsep.NewYAMLDocumentSeparator(reader)
	for {
		b, err := separator.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			logCxt.WithError(err).Error("Document separator failed")
			return nil, err
		}

		logCxt.WithField("byteLength", len(b)).Debug("Found a resource")
		r, err := createResourcesFromBytes(b)
		if err != nil {
			logCxt.WithError(err).Error("Failed to parse resource from bytes")
			return nil, err
		}

		resources = append(resources, r...)
	}

	logCxt.WithField("numResources", len(resources)).Info("Finished parsing")
	return resources, nil
}

// Implement the ResourceManager interface on the resourceHelper struct.

// GetTableDefaultHeadings returns the default headings to use in the ps-style get output
// for the resource.  Wide indicates whether the wide (true) or concise (false) column set is
// required.
func (rh resourceHelper) GetTableDefaultHeadings(wide bool) []string {
	if wide {
		return rh.tableHeadingsWide
	}

	return rh.tableHeadings
}

// GetTableTemplate constructs the go-lang template string from the supplied set of headings.
// The template separates columns using tabs so that a tabwriter can be used to pretty-print
// the table.
func (rh resourceHelper) GetTableTemplate(headings []string, printNamespace bool) (string, error) {
	if _, ok := rh.headingsMap["NAMESPACE"]; printNamespace && ok {
		headings = append([]string{"NAMESPACE"}, headings...)
	}
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

// mergeMetadataForUpdate merges the Metadata for a stored ResourceObject and a potential
// update. All metadata in the potential update will be overwritten by the stored object
// except for Labels and Annotations. This prevents accidental modifications to the metadata
// fields by forcing updates to those fields to be handled by internal or more involved
// processes.
func mergeMetadataForUpdate(old, new ResourceObject) ResourceObject {
	sm := old.GetObjectMeta()
	cm := new.GetObjectMeta()

	// Set the fields that are allowed to be overwritten (Labels and Annotations)
	// so that they will not be overwritten.
	sm.SetAnnotations(cm.GetAnnotations())
	sm.SetLabels(cm.GetLabels())

	sm.(*v1.ObjectMeta).DeepCopyInto(cm.(*v1.ObjectMeta))
	return new
}

// mergeMetadataForPatch merges the Metadata for a stored ResourceObject and a potential
// patch non-destructively. The resulting labels and annotations will be the union of
// the two sets.
func mergeMetadataForPatch(old, new ResourceObject) ResourceObject {
	sm := old.GetObjectMeta()
	cm := new.GetObjectMeta()

	// Set the fields that are allowed to be overwritten (Labels and Annotations)
	// so that they will not be overwritten.
	annotations := sm.GetAnnotations()
	for key, val := range cm.GetAnnotations() {
		if annotations == nil {
			annotations = make(map[string]string)
		}
		annotations[key] = val
	}
	labels := sm.GetLabels()
	for key, val := range cm.GetLabels() {
		if labels == nil {
			labels = make(map[string]string)
		}
		labels[key] = val
	}
	sm.SetAnnotations(annotations)
	sm.SetLabels(labels)

	sm.(*v1.ObjectMeta).DeepCopyInto(cm.(*v1.ObjectMeta))
	return new
}

// prepareMetadataForCreate removes the metadata fields that should not be set from
// calicoctl. Only the metadata fields Name, Namespace, ResourceVersion, Labels,
// and Annotations will be kept. All other fields will be set elsewhere if required.
// This prevents accidental modifications to the metadata fields by forcing updates
// to those fields to be handled by internal or more involved processes.
func prepareMetadataForCreate(r ResourceObject) ResourceObject {
	rom := r.GetObjectMeta()
	meta := &v1.ObjectMeta{}

	// Save the important fields in the meta before everything gets wiped out.
	meta.Name = rom.GetName()
	meta.Namespace = rom.GetNamespace()
	meta.ResourceVersion = rom.GetResourceVersion()
	meta.Labels = rom.GetLabels()
	meta.Annotations = rom.GetAnnotations()

	// Make a copy of the resource so the input does not get modified
	resOut := r.DeepCopyObject().(ResourceObject)
	meta.DeepCopyInto(resOut.GetObjectMeta().(*v1.ObjectMeta))
	return resOut
}
