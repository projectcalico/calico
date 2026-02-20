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

package conncheck

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"
)

func NewClient(id string, ns *v1.Namespace, opts ...ClientOption) *Client {
	if ns == nil {
		msg := fmt.Sprintf("Namespace is required for client %s", id)
		framework.Fail(msg, 1)
	}
	if id == "" {
		msg := fmt.Sprintf("ID is required for client in namespace %s", ns.Name)
		framework.Fail(msg, 1)
	}

	c := &Client{
		name:      id,
		namespace: ns,
	}
	for _, opt := range opts {
		_ = opt(c)
	}
	return c
}

type Client struct {
	name        string
	namespace   *v1.Namespace
	labels      map[string]string
	pod         *v1.Pod
	customizers []func(pod *v1.Pod)
}

// composedCustomizer returns a single customizer function that applies all
// registered customizers in order, or nil if none are registered.
func (c *Client) composedCustomizer() func(*v1.Pod) {
	if len(c.customizers) == 0 {
		return nil
	}
	return func(pod *v1.Pod) {
		for _, fn := range c.customizers {
			fn(pod)
		}
	}
}

func (c *Client) ID() string {
	return fmt.Sprintf("%s/%s", c.namespace.Name, c.name)
}

func (c *Client) Name() string {
	return c.name
}

func (c *Client) Pod() *v1.Pod {
	if c.pod == nil {
		msg := fmt.Sprintf("No pod is running for client %s/%s", c.namespace.Name, c.name)
		framework.Fail(msg, 1)
	}
	return c.pod
}

type ClientOption func(*Client) error

func WithClientLabels(labels map[string]string) ClientOption {
	return func(c *Client) error {
		c.labels = labels
		return nil
	}
}

func WithClientCustomizer(customizer func(pod *v1.Pod)) ClientOption {
	return func(c *Client) error {
		c.customizers = append(c.customizers, customizer)
		return nil
	}
}
