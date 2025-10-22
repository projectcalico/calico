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
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var (
	matchPolicy = regexp.MustCompile("^/?calico/v1/policy/([^/]+)/([^/]+)/([^/]+)$")
	typePolicy  = reflect.TypeOf(Policy{})
)

// KindIsStaged returns true if the the policy kind indicates that it is a staged policy.
func KindIsStaged(kind string) bool {
	switch kind {
	case apiv3.KindStagedNetworkPolicy,
		apiv3.KindStagedGlobalNetworkPolicy,
		apiv3.KindStagedKubernetesNetworkPolicy:
		return true
	default:
		return false
	}
}

type PolicyKey struct {
	Name      string `json:"-" validate:"required,name"`
	Namespace string `json:"-" validate:"omitempty,name"`
	Kind      string `json:"-" validate:"omitempty,name"`
}

func (key PolicyKey) defaultPath() (string, error) {
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	if key.Kind == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "kind"}
	}
	switch key.Kind {
	case apiv3.KindNetworkPolicy, apiv3.KindStagedNetworkPolicy, apiv3.KindStagedKubernetesNetworkPolicy:
		if key.Namespace == "" {
			return "", errors.ErrorInsufficientIdentifiers{Name: "namespace"}
		}
	}
	return fmt.Sprintf("/calico/v1/policy/%s/%s/%s", key.Kind, key.Namespace, key.Name), nil
}

func (key PolicyKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key PolicyKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, fmt.Errorf("defaultDeleteParentPaths is not implemented for PolicyKey")
}

func (key PolicyKey) valueType() (reflect.Type, error) {
	return typePolicy, nil
}

func (key PolicyKey) String() string {
	return fmt.Sprintf("Policy(Name=%s, Namespace=%s, Kind=%s)", key.Name, key.Namespace, key.Kind)
}

type Policy struct {
	Namespace        string                        `json:"namespace,omitempty" validate:"omitempty"`
	Tier             string                        `json:"tier,omitempty" validate:"omitempty"`
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
