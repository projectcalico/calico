// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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

package generictables

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
)

const (
	// Compromise: shorter is better for table occupancy and readability. Longer is better for
	// collision-resistance.  16 chars gives us 96 bits of entropy, which is fairly collision
	// resistant.
	HashLength = 16
)

type RuleHasher interface {
	RuleHashes(c *Chain, features *environment.Features) []string
}

type Rule struct {
	Match   MatchCriteria
	Action  Action
	Comment []string
}

type Chain struct {
	Name  string
	Rules []Rule
}

func (c *Chain) IPSetNames() (ipSetNames []string) {
	if c == nil {
		return nil
	}
	for _, rule := range c.Rules {
		if rule.Match != nil {
			ipSetNames = append(ipSetNames, rule.Match.IPSetNames()...)
		}
	}
	return
}

// ruleRenderFn takes a rule within a chain and returns a string that can be used for hashing.
type ruleRenderFn func(rule *Rule, chain string, features *environment.Features) string

// RuleHashes is a common helper function for generating a slice of hashes from a chain's rules. It relies on
// the caller passing the implementation appropriate renderFunc in order to render each Rule structure into a hashable string
// that uniquely identifies the rule.
func RuleHashes(c *Chain, renderFunc ruleRenderFn, features *environment.Features) []string {
	if c == nil {
		return nil
	}
	hashes := make([]string, len(c.Rules))

	// First hash the chain name so that identical rules in different chains will get different
	// hashes.
	s := sha256.New224()
	_, err := s.Write([]byte(c.Name))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"chain": c.Name,
		}).WithError(err).Panic("Failed to write suffix to hash.")
		return nil
	}

	hash := s.Sum(nil)
	for ii, rule := range c.Rules {
		// Each hash chains in the previous hash, so that its position in the chain and
		// the rules before it affect its hash.
		s.Reset()
		_, err = s.Write(hash)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"action":   rule.Action,
				"position": ii,
				"chain":    c.Name,
			}).WithError(err).Panic("Failed to write suffix to hash.")
		}
		ruleForHashing := renderFunc(&rule, c.Name, features)
		_, err = s.Write([]byte(ruleForHashing))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"ruleFragment": ruleForHashing,
				"action":       rule.Action,
				"position":     ii,
				"chain":        c.Name,
			}).WithError(err).Panic("Failed to write rule for hashing.")
		}
		hash = s.Sum(hash[0:0])
		// Encode the hash using a compact character set.  We use the URL-safe base64
		// variant because it uses '-' and '_', which are more shell-friendly.
		hashes[ii] = base64.RawURLEncoding.EncodeToString(hash)[:HashLength]
		if logrus.GetLevel() >= logrus.DebugLevel {
			logrus.WithFields(logrus.Fields{
				"ruleFragment": ruleForHashing,
				"action":       rule.Action,
				"position":     ii,
				"chain":        c.Name,
				"hash":         hashes[ii],
			}).Debug("Hashed rule")
		}
	}
	return hashes
}
