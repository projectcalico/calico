// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var (
	matchPolicy = regexp.MustCompile("^/?calico/v1/policy/tier/([^/]+)/policy/([^/]+)$")
	typePolicy  = reflect.TypeOf(Policy{})
)

// Policy names with this prefix are staged rather than enforced. We *could* add an additional field to the Policy
// key to relay this information and still allow the names to clash (since we want staged policies with the same name
// as their non-staged counterpart). This approach is less invasive to the existing Felix and dataplane driver code.
const PolicyNamePrefixStaged = "staged:"

// stagedToEnforcedV1Name converts the v1 name from staged (if it is) to the equivalent enforced name, and returns
// whether the original name indicated a staged policy.
func stagedToEnforcedV1Name(name string) (bool, string) {
	var namespace string
	var staged bool
	if parts := strings.Split(name, "/"); len(parts) == 2 {
		namespace, name = parts[0], parts[1]
	}
	if staged = strings.HasPrefix(name, PolicyNamePrefixStaged); staged {
		name = strings.TrimPrefix(name, PolicyNamePrefixStaged)
	}
	if namespace == "" {
		return staged, name
	}
	return staged, namespace + "/" + name
}

// PolicyIsStaged returns true if the name of the policy indicates that it is a staged policy.
func PolicyIsStaged(name string) bool {
	staged, _ := stagedToEnforcedV1Name(name)
	return staged
}

// PolicyNameLessThan checks if name1 is less that name2. Used for policy sorting. Staged policies are considered to be
// less than the non-staged equivalent.
func PolicyNameLessThan(name1, name2 string) bool {
	staged1, name1 := stagedToEnforcedV1Name(name1)
	staged2, name2 := stagedToEnforcedV1Name(name2)

	if name1 != name2 {
		return name1 < name2
	}

	if staged1 == staged2 {
		return false
	}

	// Names are equal, but staging is not. Staged policies are considered lower than enforced.
	return staged1
}

type PolicyKey struct {
	Name string `json:"-" validate:"required,name"`
	Tier string `json:"-" validate:"required,name"`
}

func (key PolicyKey) defaultPath() (string, error) {
	if key.Tier == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "tier"}
	}
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/v1/policy/tier/%s/policy/%s",
		key.Tier, escapeName(key.Name))
	return e, nil
}

func (key PolicyKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key PolicyKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key PolicyKey) valueType() (reflect.Type, error) {
	return typePolicy, nil
}

func (key PolicyKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[Policy](key, rawData)
}

func (key PolicyKey) String() string {
	return fmt.Sprintf("Policy(tier=%s, name=%s)", key.Tier, key.Name)
}

type PolicyListOptions struct {
	Name string
	Tier string
}

func (options PolicyListOptions) defaultPathRoot() string {
	k := "/calico/v1/policy/tier"
	if options.Tier == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s/policy", options.Tier)
	if options.Name == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", escapeName(options.Name))
	return k
}

func (options PolicyListOptions) KeyFromDefaultPath(path string) Key {
	log.Debugf("Get Policy key from %s", path)
	r := matchPolicy.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Debugf("Didn't match regex")
		return nil
	}
	tier := r[0][1]
	name := unescapeName(r[0][2])
	if options.Tier != "" && tier != options.Tier {
		log.Infof("Didn't match tier %s != %s", options.Tier, tier)
		return nil
	}
	if options.Name != "" && name != options.Name {
		log.Debugf("Didn't match name %s != %s", options.Name, name)
		return nil
	}
	return PolicyKey{Tier: tier, Name: name}
}

type Policy struct {
	Namespace        string                        `json:"namespace,omitempty" validate:"omitempty"`
	Order            *float64                      `json:"order,omitempty" validate:"omitempty"`
	InboundRules     []Rule                        `json:"inbound_rules,omitempty" validate:"omitempty,dive"`
	OutboundRules    []Rule                        `json:"outbound_rules,omitempty" validate:"omitempty,dive"`
	Selector         string                        `json:"selector" validate:"selector"`
	DoNotTrack       bool                          `json:"untracked,omitempty"`
	Annotations      map[string]string             `json:"annotations,omitempty"`
	PreDNAT          bool                          `json:"pre_dnat,omitempty"`
	ApplyOnForward   bool                          `json:"apply_on_forward,omitempty"`
	Types            []string                      `json:"types,omitempty"`
	PerformanceHints []apiv3.PolicyPerformanceHint `json:"performance_hints,omitempty" validate:"omitempty,unique,dive,oneof=AssumeNeededOnEveryNode"`
	StagedAction     *apiv3.StagedAction           `json:"staged_action,omitempty"`
}

func (p Policy) String() string {
	parts := make([]string, 0)
	if p.Order != nil {
		parts = append(parts, fmt.Sprintf("order:%v", *p.Order))
	}
	parts = append(parts, fmt.Sprintf("selector:%#v", p.Selector))
	inRules := make([]string, len(p.InboundRules))
	for ii, rule := range p.InboundRules {
		inRules[ii] = rule.String()
	}
	parts = append(parts, fmt.Sprintf("inbound:%v", strings.Join(inRules, ";")))
	outRules := make([]string, len(p.OutboundRules))
	for ii, rule := range p.OutboundRules {
		outRules[ii] = rule.String()
	}
	parts = append(parts, fmt.Sprintf("outbound:%v", strings.Join(outRules, ";")))
	parts = append(parts, fmt.Sprintf("untracked:%v", p.DoNotTrack))
	parts = append(parts, fmt.Sprintf("pre_dnat:%v", p.PreDNAT))
	parts = append(parts, fmt.Sprintf("apply_on_forward:%v", p.ApplyOnForward))
	parts = append(parts, fmt.Sprintf("types:%v", strings.Join(p.Types, ";")))
	if len(p.PerformanceHints) > 0 {
		parts = append(parts, fmt.Sprintf("performance_hints:%v", p.PerformanceHints))
	}
	if p.StagedAction != nil {
		parts = append(parts, fmt.Sprintf("staged_action:%v", p.StagedAction))
	}
	return strings.Join(parts, ",")
}
