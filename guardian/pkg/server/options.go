// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package server

// InboundProxyServerOption is a common format for New() options
type InboundProxyServerOption func(service *inboundProxyServer) error

// WithProxyTargets sets the proxying targets. This can be called multiple times to add
// to a union of target.
func WithProxyTargets(tgts []Target) InboundProxyServerOption {
	return func(c *inboundProxyServer) error {
		c.targets = append(c.targets, tgts...)
		return nil
	}
}

// OutboundProxyServerOption is a common format for New() options
type OutboundProxyServerOption func(service *outboundProxyServer) error

func WithListenPort(port string) OutboundProxyServerOption {
	return func(c *outboundProxyServer) error {
		c.listenPort = port
		return nil
	}
}
