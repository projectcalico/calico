// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
//
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

package model

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/namespace"
)

type resourceInfo interface {
	TypeOf() reflect.Type
	Plural() string
	KindLower() string
	Kind() string
	ParseValue(key ResourceKey, data []byte) (any, error)
}

// Name/type information about a single resource.
type resourceInfoTyped[V any] struct {
	typeOf    reflect.Type
	plural    string
	kindLower string
	kind      string
}

var _ resourceInfo = &resourceInfoTyped[any]{}

func (ri resourceInfoTyped[V]) TypeOf() reflect.Type {
	return ri.typeOf
}

func (ri resourceInfoTyped[V]) ParseValue(key ResourceKey, data []byte) (any, error) {
	return parseJSONPointer[V](key, data)
}

func (ri resourceInfoTyped[V]) Plural() string {
	return ri.plural
}

func (ri resourceInfoTyped[V]) KindLower() string {
	return ri.kindLower
}

func (ri resourceInfoTyped[V]) Kind() string {
	return ri.kind
}

var (
	matchGlobalResource     = regexp.MustCompile("^/calico/resources/v3/projectcalico[.]org/([^/]+)/([^/]+)$")
	matchNamespacedResource = regexp.MustCompile("^/calico/resources/v3/projectcalico[.]org/([^/]+)/([^/]+)/([^/]+)$")
	resourceInfoByKindLower = make(map[string]resourceInfo)
	resourceInfoByPlural    = make(map[string]resourceInfo)
)

func registerResourceInfo[V any](kind string, plural string) {
	kindLower := strings.ToLower(kind)
	plural = strings.ToLower(plural)
	var v V
	ri := resourceInfoTyped[V]{
		typeOf:    reflect.TypeOf(v),
		kindLower: kindLower,
		kind:      kind,
		plural:    plural,
	}
	resourceInfoByKindLower[kindLower] = ri
	resourceInfoByPlural[plural] = ri
}

func AllResourcePlurals() []string {
	plurals := make([]string, 0, len(resourceInfoByPlural))
	for plural := range resourceInfoByPlural {
		plurals = append(plurals, plural)
	}
	return plurals
}

func init() {
	// Register projectcalico.org/v3 resources.
	registerResourceInfo[apiv3.BGPPeer](apiv3.KindBGPPeer, "bgppeers")
	registerResourceInfo[apiv3.BGPConfiguration](apiv3.KindBGPConfiguration, "bgpconfigurations")
	registerResourceInfo[apiv3.ClusterInformation](apiv3.KindClusterInformation, "clusterinformations")
	registerResourceInfo[apiv3.FelixConfiguration](apiv3.KindFelixConfiguration, "felixconfigurations")
	registerResourceInfo[apiv3.GlobalNetworkPolicy](apiv3.KindGlobalNetworkPolicy, "globalnetworkpolicies")
	registerResourceInfo[apiv3.StagedGlobalNetworkPolicy](apiv3.KindStagedGlobalNetworkPolicy, "stagedglobalnetworkpolicies")
	registerResourceInfo[apiv3.HostEndpoint](apiv3.KindHostEndpoint, "hostendpoints")
	registerResourceInfo[apiv3.GlobalNetworkSet](apiv3.KindGlobalNetworkSet, "globalnetworksets")
	registerResourceInfo[apiv3.IPPool](apiv3.KindIPPool, "ippools")
	registerResourceInfo[apiv3.IPReservation](apiv3.KindIPReservation, "ipreservations")
	registerResourceInfo[apiv3.NetworkPolicy](apiv3.KindNetworkPolicy, "networkpolicies")
	registerResourceInfo[apiv3.StagedNetworkPolicy](apiv3.KindStagedNetworkPolicy, "stagednetworkpolicies")
	registerResourceInfo[apiv3.StagedKubernetesNetworkPolicy](apiv3.KindStagedKubernetesNetworkPolicy, "stagedkubernetesnetworkpolicies")
	registerResourceInfo[discovery.EndpointSlice](KindKubernetesEndpointSlice, "kubernetesendpointslices")
	registerResourceInfo[apiv3.NetworkSet](apiv3.KindNetworkSet, "networksets")
	registerResourceInfo[apiv3.Tier](apiv3.KindTier, "tiers")
	registerResourceInfo[apiv3.CalicoNodeStatus](apiv3.KindCalicoNodeStatus, "caliconodestatuses")
	registerResourceInfo[apiv3.Profile](apiv3.KindProfile, "profiles")
	registerResourceInfo[apiv3.KubeControllersConfiguration](apiv3.KindKubeControllersConfiguration, "kubecontrollersconfigurations")
	registerResourceInfo[apiv3.BGPFilter](apiv3.KindBGPFilter, "BGPFilters")
	registerResourceInfo[apiv3.IPAMConfiguration](apiv3.KindIPAMConfiguration, "ipamconfigurations")

	// Register libcalico-go/v3 resources.
	registerResourceInfo[internalapi.Node](internalapi.KindNode, "nodes")
	registerResourceInfo[internalapi.WorkloadEndpoint](internalapi.KindWorkloadEndpoint, "workloadendpoints")
	registerResourceInfo[internalapi.IPAMConfig](internalapi.KindIPAMConfig, "ipamconfigs")
	registerResourceInfo[internalapi.BlockAffinity](internalapi.KindBlockAffinity, "blockaffinities")
	registerResourceInfo[internalapi.LiveMigration](internalapi.KindLiveMigration, "livemigrations")

	// Register Kubernetes resources.
	registerResourceInfo[kapiv1.Service](KindKubernetesService, "kubernetesservice")
	registerResourceInfo[apiv3.NetworkPolicy](KindKubernetesNetworkPolicy, "kubernetesnetworkpolicies")
	registerResourceInfo[apiv3.GlobalNetworkPolicy](KindKubernetesClusterNetworkPolicy, "kubernetesclusternetworkpolicies")
}

type ResourceKey struct {
	// The name of the resource.
	Name string
	// The namespace of the resource.  Not required if the resource is not namespaced.
	Namespace string
	// The resource kind.
	Kind string
}

func (key ResourceKey) defaultPath() (string, error) {
	return key.defaultDeletePath()
}

func (key ResourceKey) defaultDeletePath() (string, error) {
	ri, ok := resourceInfoByKindLower[strings.ToLower(key.Kind)]
	if !ok {
		return "", fmt.Errorf("couldn't convert key: %+v", key)
	}
	if namespace.IsNamespaced(key.Kind) {
		return fmt.Sprintf("/calico/resources/v3/projectcalico.org/%s/%s/%s", ri.Plural(), key.Namespace, key.Name), nil
	}
	return fmt.Sprintf("/calico/resources/v3/projectcalico.org/%s/%s", ri.Plural(), key.Name), nil
}

func (key ResourceKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key ResourceKey) valueType() (reflect.Type, error) {
	ri, ok := resourceInfoByKindLower[strings.ToLower(key.Kind)]
	if !ok {
		return nil, fmt.Errorf("unknown resource kind: %s", key.Kind)
	}
	return ri.TypeOf(), nil
}

func (key ResourceKey) parseValue(rawData []byte) (any, error) {
	ri, ok := resourceInfoByKindLower[strings.ToLower(key.Kind)]
	if !ok {
		return nil, fmt.Errorf("unknown resource kind: %s", key.Kind)
	}
	v, err := ri.ParseValue(key, rawData)
	if err != nil {
		return nil, err
	}

	// Special case handling for network policy names to handle migration of
	// names based on tier.
	switch policy := v.(type) {
	case *apiv3.NetworkPolicy:
		policy.Name, policy.Annotations, err = determinePolicyName(policy.Name, policy.Spec.Tier, policy.Annotations)
		if err != nil {
			return nil, err
		}
	case *apiv3.GlobalNetworkPolicy:
		policy.Name, policy.Annotations, err = determinePolicyName(policy.Name, policy.Spec.Tier, policy.Annotations)
		if err != nil {
			return nil, err
		}
	case *apiv3.StagedNetworkPolicy:
		policy.Name, policy.Annotations, err = determinePolicyName(policy.Name, policy.Spec.Tier, policy.Annotations)
		if err != nil {
			return nil, err
		}
	case *apiv3.StagedGlobalNetworkPolicy:
		policy.Name, policy.Annotations, err = determinePolicyName(policy.Name, policy.Spec.Tier, policy.Annotations)
		if err != nil {
			return nil, err
		}
	}

	return v, err
}

func (key ResourceKey) String() string {
	if namespace.IsNamespaced(key.Kind) {
		return fmt.Sprintf("%s(%s/%s)", key.Kind, key.Namespace, key.Name)
	}
	return fmt.Sprintf("%s(%s)", key.Kind, key.Name)
}

// GetNamespace returns the namespace field of the ResourceKey.
func (key ResourceKey) GetNamespace() string {
	return key.Namespace
}

type ResourceListOptions struct {
	// The name of the resource.
	Name string
	// The namespace of the resource.  Not required if the resource is not namespaced.
	Namespace string
	// The resource kind.
	Kind string
	// Whether the name is prefix rather than the full name.  This is only
	// supported efficiently by the etcd API.  When using the Kubernetes API,
	// a full list operation is performed and then filtered client-side.
	Prefix bool
	// LabelSelector allows filtering on the labels of the resource. This is
	// supported efficiently by the Kubernetes backend, but the etcd backend
	// implements it client-side.
	LabelSelector labels.Selector
}

func (options ResourceListOptions) GetLabelSelector() labels.Selector {
	return options.LabelSelector
}

var _ LabelSelectingListInterface = ResourceListOptions{}

// If the Kind, Namespace and Name are specified, but the Name is a prefix then the
// last segment of this path is a prefix.
func (options ResourceListOptions) IsLastSegmentIsPrefix() bool {
	return len(options.Kind) != 0 &&
		(len(options.Namespace) != 0 || !namespace.IsNamespaced(options.Kind)) &&
		len(options.Name) != 0 &&
		options.Prefix
}

func (options ResourceListOptions) KeyFromDefaultPath(path string) Key {
	ri, ok := resourceInfoByKindLower[strings.ToLower(options.Kind)]
	if !ok {
		log.Panic("Unexpected resource kind: " + options.Kind)
	}

	if namespace.IsNamespaced(options.Kind) {
		log.Debugf("Get Namespaced Resource key from %s", path)
		r := matchNamespacedResource.FindAllStringSubmatch(path, -1)
		if len(r) != 1 {
			log.Debugf("Didn't match regex")
			return nil
		}
		kindPlural := r[0][1]
		namespace := r[0][2]
		name := r[0][3]
		if len(options.Kind) == 0 {
			panic("Kind must be specified in List option but is not")
		}
		if kindPlural != ri.Plural() {
			log.Debugf("Didn't match kind %s != %s", kindPlural, kindPlural)
			return nil
		}
		if len(options.Namespace) != 0 && namespace != options.Namespace {
			log.Debugf("Didn't match namespace %s != %s", options.Namespace, namespace)
			return nil
		}
		if len(options.Name) != 0 {
			if options.Prefix && !strings.HasPrefix(name, options.Name) {
				log.Debugf("Didn't match name prefix %s != prefix(%s)", options.Name, name)
				return nil
			} else if !options.Prefix && name != options.Name {
				log.Debugf("Didn't match name %s != %s", options.Name, name)
				return nil
			}
		}
		return ResourceKey{Kind: options.Kind, Namespace: namespace, Name: name}
	}

	log.Debugf("Get Global Resource key from %s", path)
	r := matchGlobalResource.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Debugf("Didn't match regex")
		return nil
	}
	kindPlural := r[0][1]
	name := r[0][2]
	if kindPlural != ri.Plural() {
		log.Debugf("Didn't match kind %s != %s", kindPlural, ri.Plural())
		return nil
	}
	if len(options.Name) != 0 {
		if options.Prefix && !strings.HasPrefix(name, options.Name) {
			log.Debugf("Didn't match name prefix %s != prefix(%s)", options.Name, name)
			return nil
		} else if !options.Prefix && name != options.Name {
			log.Debugf("Didn't match name %s != %s", options.Name, name)
			return nil
		}
	}
	return ResourceKey{Kind: options.Kind, Name: name}
}

func (options ResourceListOptions) defaultPathRoot() string {
	ri, ok := resourceInfoByKindLower[strings.ToLower(options.Kind)]
	if !ok {
		log.Panic("Unexpected resource kind: " + options.Kind)
	}

	k := "/calico/resources/v3/projectcalico.org/" + ri.Plural()
	if namespace.IsNamespaced(options.Kind) {
		if options.Namespace == "" {
			return k
		}
		k = k + "/" + options.Namespace
	}
	if options.Name == "" {
		return k
	}
	return k + "/" + options.Name
}

func (options ResourceListOptions) String() string {
	description := "*"
	if options.Name != "" {
		description = options.Name
	}
	if options.Namespace != "" {
		description = options.Namespace + "/" + description
	}
	if options.Prefix {
		description = description + "*"
	}
	if options.LabelSelector != nil {
		description = description + " matching " + options.LabelSelector.String()
	}
	return fmt.Sprintf("%s(%s)", options.Kind, description)
}
