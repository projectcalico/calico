// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package iptables

import (
	"crypto/sha256"
	"encoding/base64"
	log "github.com/Sirupsen/logrus"
)

const (
	// Compromise: shorter is better for table occupancy and readability. Longer is better for
	// collision-resistance.  16 chars gives us 96 bits of entropy, which is fairly collision
	// resistant.
	HashLength = 16
)

type Action interface {
	ToFragment() string
}

type GotoAction struct {
	Target string
}

func (g GotoAction) ToFragment() string {
	return "--goto " + g.Target
}

type JumpAction struct {
	Target string
}

func (g JumpAction) ToFragment() string {
	return "--jump " + g.Target
}

type DropAction struct{}

func (g DropAction) ToFragment() string {
	return "--jump DROP"
}

type AcceptAction struct{}

func (g AcceptAction) ToFragment() string {
	return "--jump ACCEPT"
}

type Rule struct {
	MatchCriteria string
	Action        Action
}

type Chain struct {
	Name  string
	Rules []Rule
}

func (c *Chain) RuleHashes() []string {
	hashes := make([]string, len(c.Rules))
	// First hash the chain name so that identical rules in different chains will get different
	// hashes.
	s := sha256.New224()
	s.Write([]byte(c.Name))
	hash := s.Sum(nil)
	for ii, rule := range c.Rules {
		// Each hash chains in the previous hash, so that its position in the chain and
		// the rules before it affect its hash.
		s.Reset()
		s.Write(hash)
		s.Write([]byte(rule.MatchCriteria))
		s.Write([]byte(" "))
		s.Write([]byte(rule.Action.ToFragment()))
		hash = s.Sum(hash[0:0])
		// Encode the hash using a compact character set.  We use the URL-safe base64
		// variant because it uses '-' and '_', which are more shell-friendly.
		hashes[ii] = base64.RawURLEncoding.EncodeToString(hash)[:HashLength]
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ruleFragment": rule.MatchCriteria,
				"action":       rule.Action,
				"position":     ii,
				"chain":        c.Name,
				"hash":         hashes[ii],
			}).Debug("Hashed rule")
		}
	}
	return hashes
}
