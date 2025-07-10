// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"strings"

	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	log "github.com/sirupsen/logrus"
)

var (
	typeQoSPolicy = reflect.TypeOf(QoSPolicy{})
)

type QoSPolicyKey struct {
	Name string `json:"-" validate:"required,name"`
}

func (key QoSPolicyKey) defaultPath() (string, error) {
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/v1/qos/policy/%s", escapeName(key.Name))
	return e, nil
}

func (key QoSPolicyKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key QoSPolicyKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key QoSPolicyKey) valueType() (reflect.Type, error) {
	return typeQoSPolicy, nil
}

func (key QoSPolicyKey) String() string {
	return fmt.Sprintf("QoSPolicy(name=%s)", key.Name)
}

type QoSPolicyListOptions struct {
	Name string
}

func (options QoSPolicyListOptions) defaultPathRoot() string {
	k := "/calico/v1/qos/policy"
	if options.Name == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", escapeName(options.Name))
	return k
}

func (options QoSPolicyListOptions) KeyFromDefaultPath(path string) Key {
	log.Debugf("Get Policy key from %s", path)
	r := matchPolicy.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Debugf("Didn't match regex")
		return nil
	}
	name := unescapeName(r[0][1])
	if options.Name != "" && name != options.Name {
		log.Debugf("Didn't match name %s != %s", options.Name, name)
		return nil
	}
	return PolicyKey{Name: name}
}

type QoSPolicy struct {
	Order         *float64  `json:"order,omitempty" validate:"omitempty"`
	Selector      string    `json:"selector" validate:"selector"`
	OutboundRules []QoSRule `json:"outbound_rules,omitempty" validate:"omitempty,dive"`
}

func (q QoSPolicy) String() string {
	parts := make([]string, 0)
	if q.Order != nil {
		parts = append(parts, fmt.Sprintf("order:%v", *q.Order))
	}
	parts = append(parts, fmt.Sprintf("selector:%#v", q.Selector))
	outRules := make([]string, len(q.OutboundRules))
	for ii, rule := range q.OutboundRules {
		outRules[ii] = rule.String()
	}
	parts = append(parts, fmt.Sprintf("outbound:%v", strings.Join(outRules, ";")))
	return strings.Join(parts, ",")
}

type QoSRule struct {
	Action string `json:"action,omitempty"`

	IPVersion *int `json:"ip_version,omitempty" validate:"omitempty,ipVersion"`

	Protocol *numorstring.Protocol `json:"protocol,omitempty" validate:"omitempty"`
	DstNet   *net.IPNet            `json:"dst_net,omitempty" validate:"omitempty"`
	DstNets  []*net.IPNet          `json:"dst_nets,omitempty" validate:"omitempty"`
	DstPorts []numorstring.Port    `json:"dst_ports,omitempty" validate:"omitempty,dive"`
	Metadata *RuleMetadata         `json:"metadata,omitempty" validate:"omitempty"`
}

func (r QoSRule) String() string {
	parts := make([]string, 0)
	// Action.
	if r.Action != "" {
		parts = append(parts, r.Action)
	} else {
		parts = append(parts, "-")
	}

	// Global packet attributes that don't depend on direction.
	if r.Protocol != nil {
		parts = append(parts, r.Protocol.String())
	}

	{
		// Destination attributes. New block ensures that fromParts goes out-of-scope before
		// we calculate toParts.  This prevents copy/paste errors.
		toParts := make([]string, 0)
		if len(r.DstPorts) > 0 {
			DstPorts := make([]string, len(r.DstPorts))
			for ii, port := range r.DstPorts {
				DstPorts[ii] = port.String()
			}
			toParts = append(toParts, "ports", strings.Join(DstPorts, ","))
		}
		dstNets := r.AllDstNets()
		if len(dstNets) != 0 {
			toParts = append(toParts, "cidr", joinNets(dstNets))
		}
		if len(toParts) > 0 {
			parts = append(parts, "to")
			parts = append(parts, toParts...)
		}
	}

	return strings.Join(parts, " ")
}

func (r QoSRule) AllDstNets() []*net.IPNet {
	return combineNets(r.DstNet, r.DstNets)
}
