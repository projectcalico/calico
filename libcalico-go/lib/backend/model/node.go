// Copyright (c) 2016,2020 Tigera, Inc. All rights reserved.

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

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	typeHostMetadata  = reflect.TypeFor[HostMetadata]()
	typeOrchRefs      = reflect.TypeFor[[]OrchRef]()
	typeWireguard     = reflect.TypeFor[Wireguard]()
	matchHostMetadata = regexp.MustCompile(`^/?calico/v1/host/([^/]+)/metadata$`)
	matchWireguard    = regexp.MustCompile(`^/?calico/v1/host/([^/]+)/wireguard$`)
)

type OrchRef struct {
	Orchestrator string `json:"orchestrator,omitempty"`
	NodeName     string `json:"nodeName,omitempty"`
}

type Wireguard struct {
	InterfaceIPv4Addr *net.IP `json:"interfaceIPv4Addr,omitempty"`
	PublicKey         string  `json:"publicKey,omitempty"`
	InterfaceIPv6Addr *net.IP `json:"interfaceIPv6Addr,omitempty"`
	PublicKeyV6       string  `json:"publicKeyV6,omitempty"`
}

// HostMetadata is the primary v1 host enumeration entry — its presence in the
// datastore signals "this host exists". Tunnel addresses, BGP config, etc. are
// derived from the v3 Node resource and projected onto separate v1 keys by the
// felix node update processor.
type HostMetadata struct {
}

type HostMetadataKey struct {
	Hostname string
}

func (key HostMetadataKey) defaultPath() (string, error) {
	if key.Hostname == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	return fmt.Sprintf("/calico/v1/host/%s/metadata", key.Hostname), nil
}

func (key HostMetadataKey) defaultDeletePath() (string, error) {
	if key.Hostname == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	return fmt.Sprintf("/calico/v1/host/%s", key.Hostname), nil
}

func (key HostMetadataKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key HostMetadataKey) valueType() (reflect.Type, error) {
	return typeHostMetadata, nil
}

func (key HostMetadataKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[HostMetadata](key, rawData)
}

func (key HostMetadataKey) String() string {
	return fmt.Sprintf("Node(name=%s)", key.Hostname)
}

type HostMetadataListOptions struct {
	Hostname string
}

func (options HostMetadataListOptions) defaultPathRoot() string {
	if options.Hostname == "" {
		return "/calico/v1/host"
	} else {
		return fmt.Sprintf("/calico/v1/host/%s/metadata", options.Hostname)
	}
}

func (options HostMetadataListOptions) KeyFromDefaultPath(path string) Key {
	log.Debugf("Get Node key from %s", path)
	if r := matchHostMetadata.FindAllStringSubmatch(path, -1); len(r) == 1 {
		return HostMetadataKey{Hostname: r[0][1]}
	} else {
		log.Debugf("%s didn't match regex", path)
		return nil
	}
}

type OrchRefKey struct {
	Hostname string
}

func (key OrchRefKey) defaultPath() (string, error) {
	return fmt.Sprintf("/calico/v1/host/%s/orchestrator_refs",
		key.Hostname), nil
}

func (key OrchRefKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key OrchRefKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key OrchRefKey) valueType() (reflect.Type, error) {
	return typeOrchRefs, nil
}

func (key OrchRefKey) parseValue(rawData []byte) (any, error) {
	return parseJSONValue[[]OrchRef](key, rawData)
}

func (key OrchRefKey) String() string {
	return fmt.Sprintf("OrchRefs(nodename=%s)", key.Hostname)
}

type OrchRefListOptions struct {
	Hostname string
}

func (options OrchRefListOptions) defaultPathRoot() string {
	return fmt.Sprintf("/calico/v1/host/%s/orchestrator_refs", options.Hostname)
}

func (options OrchRefListOptions) KeyFromDefaultPath(path string) Key {
	return OrchRefKey{Hostname: options.Hostname}
}

// The Felix Wireguard Key.
type WireguardKey struct {
	NodeName string
}

func (key WireguardKey) defaultPath() (string, error) {
	if key.NodeName == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	return fmt.Sprintf("/calico/v1/host/%s/wireguard",
		key.NodeName), nil
}

func (key WireguardKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key WireguardKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key WireguardKey) valueType() (reflect.Type, error) {
	return typeWireguard, nil
}

func (key WireguardKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[Wireguard](key, rawData)
}

func (key WireguardKey) String() string {
	return fmt.Sprintf("Node(nodename=%s)", key.NodeName)
}

type WireguardListOptions struct {
	NodeName string
}

func (options WireguardListOptions) defaultPathRoot() string {
	if options.NodeName == "" {
		return "/calico/v1/host"
	} else {
		return fmt.Sprintf("/calico/v1/host/%s/wireguard", options.NodeName)
	}
}

func (options WireguardListOptions) KeyFromDefaultPath(path string) Key {
	log.Debugf("Get Node key from %s", path)
	if r := matchWireguard.FindAllStringSubmatch(path, -1); len(r) == 1 {
		return WireguardKey{NodeName: r[0][1]}
	} else {
		log.Debugf("%s didn't match regex", path)
		return nil
	}
}
