// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conncheck

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
)

type Protocol string

const (
	ICMP Protocol = "ICMP"
	TCP  Protocol = "TCP"
	HTTP Protocol = "HTTP"
)

// AccessType represents how the target is accessed. A Kubenretes pod can be accessed in a variety of ways, such as
// via a Service (ClusterIP, ServiceDNS), directly via its IP (PodIP). Some targets are not backed by a pod, such as
// a domain name.
type AccessType string

const (
	// TypeClusterIP represents a target that is accessed via the service's cluster IP.
	TypeClusterIP AccessType = "ClusterIP"

	// TypePodIP represents a target that is accessed via the pod's real IP address.
	TypePodIP AccessType = "PodIP"

	// TypeService represents a target that is accessed via the service's in-cluster DNS name.
	TypeService AccessType = "ServiceDNS"

	// TypeDomain represents a target that is accessed via a domain name. Typically used for external services.
	TypeDomain AccessType = "Domain"

	// TypeNodePort represents a target that is accessed via the service's NodePort.
	TypeNodePort AccessType = "NodePort"
)

type Target interface {
	// String returns a human-readable name for the target.
	String() string

	// Destination returns the destination of the target, combining the IP/hostname and port (if set).
	Destination() string

	// AccessType returns the way in which the target is accessed. e.g., ClusterIP, PodIP, ServiceDNS, Domain.
	AccessType() string

	// GetProtocol returns the protocol of the target.
	GetProtocol() Protocol

	// Port sets the port of the target to the given value.
	Port(int) Target

	// HTTPParams returns the HTTP Request set on the target.
	HTTPParams() *HTTPParams
}

var _ Target = &target{}

type target struct {
	server      *Server
	destination string
	port        int
	protocol    Protocol
	targetType  AccessType
	http        *HTTPParams
}

func (t *target) Destination() string {
	if t.port != 0 {
		return fmt.Sprintf("%s:%d", t.destination, t.port)
	}
	return t.destination
}

func (t *target) GetProtocol() Protocol {
	return t.protocol
}

// String returns a human-readable name for the target.
func (t *target) String() string {
	if t.server != nil {
		chunks := []string{
			fmt.Sprintf("%s/%s", t.server.Pod().Namespace, t.server.Pod().Name),
		}
		if t.port != 0 {
			chunks = append(chunks, fmt.Sprintf("%d", t.port))
		}
		if t.http != nil {
			sha := sha1.New()
			sha.Write([]byte(fmt.Sprintf("%s:%s %v", t.http.Method, t.http.Path, t.http.Headers)))
			chunks = append(chunks, base64.URLEncoding.EncodeToString(sha.Sum(nil))[:7])
		}
		return strings.Join(chunks, ":")
	}
	return t.Destination()
}

func (t *target) AccessType() string {
	return string(t.targetType)
}

func (t *target) Port(i int) Target {
	t.port = i
	return t
}

func (t *target) HTTPParams() *HTTPParams {
	return t.http
}

func NewDomainTarget(dst string) Target {
	return &target{
		destination: dst,
		targetType:  TypeDomain,
		protocol:    TCP,
	}
}

func NewPodPingTarget(pod *v1.Pod) Target {
	return &target{
		destination: pod.Status.PodIP,
		targetType:  TypePodIP,
		protocol:    ICMP,
	}
}

func NewTarget(dst string, targetType AccessType, proto Protocol) Target {
	return &target{
		destination: dst,
		targetType:  targetType,
		protocol:    proto,
	}
}

type TargetOption func(*target) error

type HTTPParams struct {
	Method  string
	Path    string
	Headers []string
}

func WithHTTP(method, path string, headers []string) TargetOption {
	return func(t *target) error {
		t.protocol = HTTP
		t.http = &HTTPParams{
			Method:  method,
			Path:    path,
			Headers: headers,
		}
		return nil
	}
}
