// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
//
//
// NOTICE:
//
// Original code pulled from k8s.io@1.29.4, package: pkg/proxy/endpoints.go.
// Adapted for legacy use in this repository.

package proxy

import (
	"net"
	"strconv"

	"k8s.io/apimachinery/pkg/util/sets"
	k8sp "k8s.io/kubernetes/pkg/proxy"
)

// endpointInfo contains base information that defines an endpoint.
type endpointInfo struct {
	// Cache this values to improve performance
	ip   string
	port int
	// endpoint is the same as net.JoinHostPort(ip,port)
	endpoint string

	// isLocal indicates whether the endpoint is running on same host as kube-proxy.
	isLocal bool

	// ready indicates whether this endpoint is ready and NOT terminating, unless
	// PublishNotReadyAddresses is set on the service, in which case it will just
	// always be true.
	ready bool
	// serving indicates whether this endpoint is ready regardless of its terminating state.
	// For pods this is true if it has a ready status regardless of its deletion timestamp.
	serving bool
	// terminating indicates whether this endpoint is terminating.
	// For pods this is true if it has a non-nil deletion timestamp.
	terminating bool

	// zoneHints represent the zone hints for the endpoint. This is based on
	// endpoint.hints.forZones[*].name in the EndpointSlice API.
	zoneHints sets.Set[string]
}

var _ k8sp.Endpoint = &endpointInfo{}

// NewEndpointInfo creates a new endpointInfo, returning it as a k8s proxy Endpoint.
func NewEndpointInfo(ip string, port int, isLocal, ready, serving, terminating bool, zoneHints sets.Set[string]) k8sp.Endpoint {
	return &endpointInfo{
		ip:          ip,
		port:        port,
		endpoint:    net.JoinHostPort(ip, strconv.Itoa(port)),
		isLocal:     isLocal,
		ready:       ready,
		serving:     serving,
		terminating: terminating,
		zoneHints:   zoneHints,
	}
}

// String is part of proxy.Endpoint interface.
func (info *endpointInfo) String() string {
	return info.endpoint
}

// IP returns just the IP part of the endpoint, it's a part of proxy.Endpoint interface.
func (info *endpointInfo) IP() string {
	return info.ip
}

// Port returns just the Port part of the endpoint.
func (info *endpointInfo) Port() int {
	return info.port
}

// IsLocal is part of proxy.Endpoint interface.
func (info *endpointInfo) IsLocal() bool {
	return info.isLocal
}

// IsReady returns true if an endpoint is ready and not terminating.
func (info *endpointInfo) IsReady() bool {
	return info.ready
}

// IsServing returns true if an endpoint is ready, regardless of if the
// endpoint is terminating.
func (info *endpointInfo) IsServing() bool {
	return info.serving
}

// IsTerminating retruns true if an endpoint is terminating. For pods,
// that is any pod with a deletion timestamp.
func (info *endpointInfo) IsTerminating() bool {
	return info.terminating
}

// ZoneHints returns the zone hint for the endpoint.
func (info *endpointInfo) ZoneHints() sets.Set[string] {
	return info.zoneHints
}
