// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"unique"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	matchWorkloadEndpoint = regexp.MustCompile("^/?calico/v1/host/([^/]+)/workload/([^/]+)/([^/]+)/endpoint/([^/]+)$")
)

// WorkloadEndpointKey is the interface for all workload endpoint key variants.
type WorkloadEndpointKey interface {
	EndpointKey
	OrchestratorID() string
	WorkloadID() string
	EndpointID() string
	GetNamespace() string
}

// MakeWorkloadEndpointKey creates a new WorkloadEndpointKey, picking the most
// compact variant based on the orchestrator and endpoint ID values.
func MakeWorkloadEndpointKey(hostname, orchestratorID, workloadID, endpointID string) WorkloadEndpointKey {
	if orchestratorID == "k8s" {
		if endpointID == "eth0" {
			return K8sDefaultWEPKey{
				hostname:   unique.Make(hostname),
				workloadID: unique.Make(workloadID),
			}
		}
		return K8sWEPKey{
			hostname:   unique.Make(hostname),
			workloadID: unique.Make(workloadID),
			endpointID: unique.Make(endpointID),
		}
	}
	return GenericWEPKey{
		hostname:       unique.Make(hostname),
		orchestratorID: unique.Make(orchestratorID),
		workloadID:     unique.Make(workloadID),
		endpointID:     unique.Make(endpointID),
	}
}

// WorkloadEndpointKeyTypes returns an instance of each concrete WEP key variant,
// for use with dispatcher registration or reflection.
func WorkloadEndpointKeyTypes() []WorkloadEndpointKey {
	return []WorkloadEndpointKey{GenericWEPKey{}, K8sWEPKey{}, K8sDefaultWEPKey{}}
}

// Shared helper functions for all WEP key variants.

func wepDefaultPath(key WorkloadEndpointKey) (string, error) {
	if key.Host() == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "node"}
	}
	if key.OrchestratorID() == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "orchestrator"}
	}
	if key.WorkloadID() == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "workload"}
	}
	if key.EndpointID() == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	return fmt.Sprintf("/calico/v1/host/%s/workload/%s/%s/endpoint/%s",
		key.Host(), escapeName(key.OrchestratorID()), escapeName(key.WorkloadID()), escapeName(key.EndpointID())), nil
}

func wepDefaultDeleteParentPaths(key WorkloadEndpointKey) ([]string, error) {
	if key.Host() == "" {
		return nil, errors.ErrorInsufficientIdentifiers{Name: "node"}
	}
	if key.OrchestratorID() == "" {
		return nil, errors.ErrorInsufficientIdentifiers{Name: "orchestrator"}
	}
	if key.WorkloadID() == "" {
		return nil, errors.ErrorInsufficientIdentifiers{Name: "workload"}
	}
	workload := fmt.Sprintf("/calico/v1/host/%s/workload/%s/%s",
		key.Host(), escapeName(key.OrchestratorID()), escapeName(key.WorkloadID()))
	endpoints := workload + "/endpoint"
	return []string{endpoints, workload}, nil
}

var typeWorkloadEndpoint = reflect.TypeOf(WorkloadEndpoint{})

func wepString(key WorkloadEndpointKey) string {
	return fmt.Sprintf("WorkloadEndpoint(node=%s, orchestrator=%s, workload=%s, name=%s)",
		key.Host(), key.OrchestratorID(), key.WorkloadID(), key.EndpointID())
}

func wepGetNamespace(key WorkloadEndpointKey) string {
	parts := strings.SplitN(key.WorkloadID(), "/", 2)
	if len(parts) == 2 {
		return parts[0]
	}
	return ""
}

// GenericWEPKey is a fully general workload endpoint key with all 4 fields stored.
// Used for non-k8s orchestrators (rare in production).
type GenericWEPKey struct {
	hostname       unique.Handle[string]
	orchestratorID unique.Handle[string]
	workloadID     unique.Handle[string]
	endpointID     unique.Handle[string]
}

func (key GenericWEPKey) WorkloadOrHostEndpointKey()         {}
func (key GenericWEPKey) Host() string                       { return key.hostname.Value() }
func (key GenericWEPKey) OrchestratorID() string             { return key.orchestratorID.Value() }
func (key GenericWEPKey) WorkloadID() string                 { return key.workloadID.Value() }
func (key GenericWEPKey) EndpointID() string                 { return key.endpointID.Value() }
func (key GenericWEPKey) GetNamespace() string               { return wepGetNamespace(key) }
func (key GenericWEPKey) String() string                     { return wepString(key) }
func (key GenericWEPKey) defaultPath() (string, error)       { return wepDefaultPath(key) }
func (key GenericWEPKey) defaultDeletePath() (string, error) { return wepDefaultPath(key) }
func (key GenericWEPKey) defaultDeleteParentPaths() ([]string, error) {
	return wepDefaultDeleteParentPaths(key)
}
func (key GenericWEPKey) valueType() (reflect.Type, error) { return typeWorkloadEndpoint, nil }
func (key GenericWEPKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[WorkloadEndpoint](key, rawData)
}

// K8sWEPKey is a Kubernetes workload endpoint key with a non-default endpoint ID.
// OrchestratorID() returns "k8s" without storing it.
type K8sWEPKey struct {
	hostname   unique.Handle[string]
	workloadID unique.Handle[string]
	endpointID unique.Handle[string]
}

func (key K8sWEPKey) WorkloadOrHostEndpointKey()         {}
func (key K8sWEPKey) Host() string                       { return key.hostname.Value() }
func (key K8sWEPKey) OrchestratorID() string             { return "k8s" }
func (key K8sWEPKey) WorkloadID() string                 { return key.workloadID.Value() }
func (key K8sWEPKey) EndpointID() string                 { return key.endpointID.Value() }
func (key K8sWEPKey) GetNamespace() string               { return wepGetNamespace(key) }
func (key K8sWEPKey) String() string                     { return wepString(key) }
func (key K8sWEPKey) defaultPath() (string, error)       { return wepDefaultPath(key) }
func (key K8sWEPKey) defaultDeletePath() (string, error) { return wepDefaultPath(key) }
func (key K8sWEPKey) defaultDeleteParentPaths() ([]string, error) {
	return wepDefaultDeleteParentPaths(key)
}
func (key K8sWEPKey) valueType() (reflect.Type, error) { return typeWorkloadEndpoint, nil }
func (key K8sWEPKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[WorkloadEndpoint](key, rawData)
}

// K8sDefaultWEPKey is a Kubernetes workload endpoint key with the default "eth0" endpoint.
// Both OrchestratorID and EndpointID are implicit, saving storage.
type K8sDefaultWEPKey struct {
	hostname   unique.Handle[string]
	workloadID unique.Handle[string]
}

func (key K8sDefaultWEPKey) WorkloadOrHostEndpointKey()         {}
func (key K8sDefaultWEPKey) Host() string                       { return key.hostname.Value() }
func (key K8sDefaultWEPKey) OrchestratorID() string             { return "k8s" }
func (key K8sDefaultWEPKey) WorkloadID() string                 { return key.workloadID.Value() }
func (key K8sDefaultWEPKey) EndpointID() string                 { return "eth0" }
func (key K8sDefaultWEPKey) GetNamespace() string               { return wepGetNamespace(key) }
func (key K8sDefaultWEPKey) String() string                     { return wepString(key) }
func (key K8sDefaultWEPKey) defaultPath() (string, error)       { return wepDefaultPath(key) }
func (key K8sDefaultWEPKey) defaultDeletePath() (string, error) { return wepDefaultPath(key) }
func (key K8sDefaultWEPKey) defaultDeleteParentPaths() ([]string, error) {
	return wepDefaultDeleteParentPaths(key)
}
func (key K8sDefaultWEPKey) valueType() (reflect.Type, error) { return typeWorkloadEndpoint, nil }
func (key K8sDefaultWEPKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[WorkloadEndpoint](key, rawData)
}

// Compile-time interface checks.
var (
	_ WorkloadEndpointKey = GenericWEPKey{}
	_ WorkloadEndpointKey = K8sWEPKey{}
	_ WorkloadEndpointKey = K8sDefaultWEPKey{}
)

type WorkloadEndpointListOptions struct {
	Hostname       string
	OrchestratorID string
	WorkloadID     string
	EndpointID     string
}

func (options WorkloadEndpointListOptions) defaultPathRoot() string {
	k := "/calico/v1/host"
	if options.Hostname == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s/workload", options.Hostname)
	if options.OrchestratorID == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", escapeName(options.OrchestratorID))
	if options.WorkloadID == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s/endpoint", escapeName(options.WorkloadID))
	if options.EndpointID == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", escapeName(options.EndpointID))
	return k
}

func (options WorkloadEndpointListOptions) KeyFromDefaultPath(path string) Key {
	log.Debugf("Get WorkloadEndpoint key from %s", path)
	r := matchWorkloadEndpoint.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Debugf("Didn't match regex")
		return nil
	}
	hostname := r[0][1]
	orch := unescapeName(r[0][2])
	workload := unescapeName(r[0][3])
	endpointID := unescapeName(r[0][4])
	if options.Hostname != "" && hostname != options.Hostname {
		log.Debugf("Didn't match hostname %s != %s", options.Hostname, hostname)
		return nil
	}
	if options.OrchestratorID != "" && orch != options.OrchestratorID {
		log.Debugf("Didn't match orchestrator %s != %s", options.OrchestratorID, orch)
		return nil
	}
	if options.WorkloadID != "" && workload != options.WorkloadID {
		log.Debugf("Didn't match workload %s != %s", options.WorkloadID, workload)
		return nil
	}
	if options.EndpointID != "" && endpointID != options.EndpointID {
		log.Debugf("Didn't match endpoint ID %s != %s", options.EndpointID, endpointID)
		return nil
	}
	return MakeWorkloadEndpointKey(hostname, orch, workload, endpointID)
}

type WorkloadEndpoint struct {
	State                      string            `json:"state"`
	Name                       string            `json:"name"`
	ActiveInstanceID           string            `json:"active_instance_id"`
	Mac                        *net.MAC          `json:"mac"`
	ProfileIDs                 []string          `json:"profile_ids"`
	IPv4Nets                   []net.IPNet       `json:"ipv4_nets"`
	IPv6Nets                   []net.IPNet       `json:"ipv6_nets"`
	IPv4NAT                    []IPNAT           `json:"ipv4_nat,omitempty"`
	IPv6NAT                    []IPNAT           `json:"ipv6_nat,omitempty"`
	Labels                     uniquelabels.Map  `json:"labels,omitempty"`
	IPv4Gateway                *net.IP           `json:"ipv4_gateway,omitempty" validate:"omitempty,ipv4"`
	IPv6Gateway                *net.IP           `json:"ipv6_gateway,omitempty" validate:"omitempty,ipv6"`
	Ports                      []EndpointPort    `json:"ports,omitempty" validate:"dive"`
	GenerateName               string            `json:"generate_name,omitempty"`
	AllowSpoofedSourcePrefixes []net.IPNet       `json:"allow_spoofed_source_ips,omitempty"`
	Annotations                map[string]string `json:"annotations,omitempty"`
	QoSControls                *QoSControls      `json:"qosControls,omitempty"`
}

func (e *WorkloadEndpoint) WorkloadOrHostEndpoint() {}

func (e *WorkloadEndpoint) GetLabels() uniquelabels.Map {
	return e.Labels
}

func (e *WorkloadEndpoint) GetProfileIDs() []string {
	return e.ProfileIDs
}

func (e *WorkloadEndpoint) GetPorts() []EndpointPort {
	return e.Ports
}

var _ Endpoint = (*WorkloadEndpoint)(nil)

// IPNat contains a single NAT mapping for a WorkloadEndpoint resource.
type IPNAT struct {
	// The internal IP address which must be associated with the owning endpoint via the
	// configured IPNetworks for the endpoint.
	IntIP net.IP `json:"int_ip" validate:"ip"`

	// The external IP address.
	ExtIP net.IP `json:"ext_ip" validate:"ip"`
}

type QoSControls = v3.QoSControls
