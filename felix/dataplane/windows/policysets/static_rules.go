// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package policysets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dataplane/windows/hns"
)

const (
	// static rule file name
	StaticFileName = "static-rules.json"
)

var (
	ErrNoRuleSpecified = errors.New("no rule specified")
)

type staticACLRule struct {
	Type            hns.PolicyType    `json:"Type"`
	Id              string            `json:"ID"`
	Protocol        uint16            `json:"Protocol"`
	Action          hns.ActionType    `json:"Action"`
	Direction       hns.DirectionType `json:"Direction"`
	LocalAddresses  string            `json:"LocalAddresses,omitempty"`
	RemoteAddresses string            `json:"RemoteAddresses,omitempty"`
	LocalPorts      string            `json:"LocalPorts,omitempty"`
	RemotePorts     string            `json:"RemotePorts,omitempty"`
	RuleType        hns.RuleType      `json:"RuleType"`
	Priority        uint16            `json:"Priority"`
}

func (p staticACLRule) ToHnsACLPolicy(prefix string) (*hns.ACLPolicy, error) {
	if len(p.Id) == 0 {
		return nil, fmt.Errorf("'Id' is missing")
	}
	if p.Priority == 0 {
		return nil, fmt.Errorf("'Priority' should not be zero")
	}
	if p.Type != hns.ACL {
		return nil, fmt.Errorf("'Type' is not ACL")
	}
	if (p.RuleType != hns.Host) && (p.RuleType != hns.Switch) {
		return nil, fmt.Errorf("'RuleType' %s is invalid", p.RuleType)
	}
	if (p.Action != hns.Allow) && (p.Action != hns.Block) {
		return nil, fmt.Errorf("'Action' %s is invalid", p.Action)
	}
	if (p.Direction != hns.In) && (p.Direction != hns.Out) {
		return nil, fmt.Errorf("'Direction' %s is invalid", p.Direction)
	}

	return &hns.ACLPolicy{
		Type:            p.Type,
		Id:              prefix + "-" + p.Id,
		Protocol:        p.Protocol,
		Action:          p.Action,
		Direction:       p.Direction,
		LocalAddresses:  p.LocalAddresses,
		RemoteAddresses: p.RemoteAddresses,
		LocalPorts:      p.LocalPorts,
		RemotePorts:     p.RemotePorts,
		RuleType:        p.RuleType,
		Priority:        p.Priority,
	}, nil
}

type staticEndpointPolicy struct {
	Name string        `json:"Name"`
	Rule staticACLRule `json:"Rule"`
}

type staticEndpointPolicies struct {
	Provider string                 `json:"Provider"`
	Version  string                 `json:"Version"`
	Rules    []staticEndpointPolicy `json:"Rules"`
}

// staticRulesReader is a wrapper to read a file.
// So we can have a mock reader for UT.
type StaticRulesReader interface {
	ReadData() ([]byte, error)
}

type FileReader string

func (f FileReader) ReadData() ([]byte, error) {
	// The value of os.Args[0] is "c:\CalicoWindows\calico-node.exe" which
	// is the executable for CalicoFelix service. The static rules file is located
	// at same directory with "calico-node.exe".
	rootDir := filepath.Dir(os.Args[0])
	ruleFile := filepath.Join(rootDir, string(f))

	if _, err := os.Stat(ruleFile); os.IsNotExist(err) {
		return []byte{}, ErrNoRuleSpecified
	}
	return os.ReadFile(ruleFile)
}

// Read ACL policy rules from static rule file.
func readStaticRules(r StaticRulesReader) (policies []*hns.ACLPolicy) {
	data, err := r.ReadData()
	if err == ErrNoRuleSpecified {
		log.Info("Ignoring absent static rules file")
		return
	}

	// If anything wrong with static rules file, Felix should panic.
	if err != nil {
		log.WithError(err).Panic("Failed to read static rules file.")
	}

	staticPolicies := staticEndpointPolicies{}

	if err = json.Unmarshal(data, &staticPolicies); err != nil {
		log.WithError(err).Panicf("Failed to unmarshal static rules file <provider %s, version %s>.",
			staticPolicies.Provider, staticPolicies.Version)
	}

	if len(staticPolicies.Provider) == 0 {
		log.WithError(err).Panic("Provider is not specified")
	}

	for _, r := range staticPolicies.Rules {
		if r.Rule.Type != hns.ACL {
			log.WithField("static rules", r.Rule).Panic("Incorrect static rule")
		}
		hnsRule, err := r.Rule.ToHnsACLPolicy(staticPolicies.Provider)
		if err != nil {
			log.WithError(err).Panic("Failed to convert static rule to ACL rule.")
		}
		log.WithField("static ACL rules", hnsRule).Info("Reading static ACL rules")
		policies = append(policies, hnsRule)
	}

	return
}
