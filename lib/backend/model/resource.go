// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/namespace"
)

var (
	matchGlobalResource     = regexp.MustCompile("^/calico/resources/v2/([^/]+)/([^/]+)$")
	matchNamespacedResource = regexp.MustCompile("^/calico/resources/v2/([^/]+)/([^/]+)/([^/]+)$")
	kindToType              = map[string]reflect.Type{
		strings.ToLower(apiv2.KindBGPPeer):             reflect.TypeOf(apiv2.BGPPeer{}),
		strings.ToLower(apiv2.KindGlobalNetworkPolicy): reflect.TypeOf(apiv2.GlobalNetworkPolicy{}),
		strings.ToLower(apiv2.KindHostEndpoint):        reflect.TypeOf(apiv2.HostEndpoint{}),
		strings.ToLower(apiv2.KindIPPool):              reflect.TypeOf(apiv2.IPPool{}),
		strings.ToLower(apiv2.KindNetworkPolicy):       reflect.TypeOf(apiv2.NetworkPolicy{}),
		strings.ToLower(apiv2.KindNode):                reflect.TypeOf(apiv2.Node{}),
		strings.ToLower(apiv2.KindProfile):             reflect.TypeOf(apiv2.Profile{}),
		strings.ToLower(apiv2.KindWorkloadEndpoint):    reflect.TypeOf(apiv2.WorkloadEndpoint{}),
	}
)

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
	if namespace.IsNamespaced(key.Kind) {
		return fmt.Sprintf("/calico/resources/v2/%s/%s/%s", strings.ToLower(key.Kind), key.Namespace, key.Name), nil
	}
	return fmt.Sprintf("/calico/resources/v2/%s/%s", strings.ToLower(key.Kind), key.Name), nil
}

func (key ResourceKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key ResourceKey) valueType() reflect.Type {
	t := kindToType[strings.ToLower(key.Kind)]
	if t == nil {
		log.Fatal("Unexpected resource kind: " + key.Kind)
	}
	return t
}

func (key ResourceKey) String() string {
	if namespace.IsNamespaced(key.Kind) {
		return fmt.Sprintf("%s(%s/%s)", key.Kind, key.Namespace, key.Name)
	}
	return fmt.Sprintf("%s(%s)", key.Kind, key.Name)
}

type ResourceListOptions struct {
	// The name of the resource.
	Name string
	// The namespace of the resource.  Not required if the resource is not namespaced.
	Namespace string
	// The resource kind.
	Kind string
}

func (options ResourceListOptions) KeyFromDefaultPath(path string) Key {
	if len(options.Kind) == 0 {
		log.Fatal("Kind must be specified in List option but is not")
	}

	if namespace.IsNamespaced(options.Kind) {
		log.Debugf("Get Namespaced Resource key from %s", path)
		r := matchNamespacedResource.FindAllStringSubmatch(path, -1)
		if len(r) != 1 {
			log.Debugf("Didn't match regex")
			return nil
		}
		kind := r[0][1]
		namespace := r[0][2]
		name := r[0][3]
		if len(options.Kind) == 0 {
			panic("Kind must be specified in List option but is not")
		}
		if kind != strings.ToLower(options.Kind) {
			log.Debugf("Didn't match kind %s != %s", options.Kind, kind)
			return nil
		}
		if len(options.Namespace) != 0 && namespace != options.Namespace {
			log.Debugf("Didn't match namespace %s != %s", options.Namespace, namespace)
			return nil
		}
		if len(options.Name) != 0 && name != options.Name {
			log.Debugf("Didn't match name %s != %s", options.Name, name)
			return nil
		}
		return ResourceKey{Kind: options.Kind, Namespace: namespace, Name: name}
	}

	log.Debugf("Get Global Resource key from %s", path)
	r := matchGlobalResource.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Debugf("Didn't match regex")
		return nil
	}
	kind := r[0][1]
	name := r[0][2]
	if kind != strings.ToLower(options.Kind) {
		log.Debugf("Didn't match name %s != %s", options.Kind, kind)
		return nil
	}
	if len(options.Name) != 0 && name != options.Name {
		log.Debugf("Didn't match name %s != %s", options.Name, name)
		return nil
	}
	return ResourceKey{Kind: options.Kind, Name: name}
}

func (options ResourceListOptions) defaultPathRoot() string {
	if len(options.Kind) == 0 {
		log.Fatal("Kind must be specified in List option but is not")
	}

	k := "/calico/resources/v2/" + strings.ToLower(options.Kind)
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
