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
	"fmt"
	"regexp"
	"strings"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"
)

var shellUnsafe = regexp.MustCompile(`[^\w @%+=:,./-]`)

const (
	// Compromise: shorter is better for table occupancy and readability. Longer is better for
	// collision-resistance.  16 chars gives us 96 bits of entropy, which is fairly collision
	// resistant.
	HashLength = 16
)

type Rule struct {
	Match   MatchCriteria
	Action  Action
	Comment []string
}

// renderFunc takes a list of fragments, a prefix fragment, a MatchCriteria, an Action, a comment, and a set of features
// and renders them into a string suitable for programming into the dataplane. The way rules are rendered varies between iptables and nftables.
type renderFunc func(fragments []string, prefixFragment string, match MatchCriteria, action Action, comment []string, features *environment.Features) string

// TODO: This is a bit of a mess. We have distinct Render() for nftables, and RenderX() for iptables which are mutually exclusive.
// There is probably a better way to structure this.
func (r Rule) Render(chain string, prefixFragment string, renderInner renderFunc, features *environment.Features) *knftables.Rule {
	return &knftables.Rule{
		Chain:   chain,
		Rule:    renderInner([]string{}, "", r.Match, r.Action, nil, features),
		Comment: r.comment(prefixFragment),
	}
}

func (r Rule) RenderAppend(chainName, prefixFragment string, renderInner renderFunc, features *environment.Features) string {
	fragments := make([]string, 0, 6)
	if _, ok := r.Match.(NFTMatchCriteria); ok {
		// This is an nftables rule. Use nftables syntax instead.
		fragments = append(fragments, "add rule", chainName)
	} else {
		fragments = append(fragments, "-A", chainName)
	}
	return renderInner(fragments, prefixFragment, r.Match, r.Action, r.Comment, features)
}

// TODO: iptables only
func (r Rule) RenderInsert(chainName, prefixFragment string, renderInner renderFunc, features *environment.Features) string {
	fragments := make([]string, 0, 6)
	fragments = append(fragments, "-I", chainName)
	return renderInner(fragments, prefixFragment, r.Match, r.Action, r.Comment, features)
}

// TODO: iptables only
func (r Rule) RenderInsertAtRuleNumber(chainName string, ruleNum int, prefixFragment string, renderInner renderFunc, features *environment.Features) string {
	fragments := make([]string, 0, 7)
	fragments = append(fragments, "-I", chainName, fmt.Sprintf("%d", ruleNum))
	return renderInner(fragments, prefixFragment, r.Match, r.Action, r.Comment, features)
}

// TODO: iptables only
func (r Rule) RenderReplace(chainName string, ruleNum int, prefixFragment string, renderInner renderFunc, features *environment.Features) string {
	fragments := make([]string, 0, 7)
	fragments = append(fragments, "-R", chainName, fmt.Sprintf("%d", ruleNum))
	return renderInner(fragments, prefixFragment, r.Match, r.Action, r.Comment, features)
}

// TODO: This is just for nftables mode.
func (r Rule) comment(prefixFragment string) *string {
	// ALways include the prefixFragment, which includes the chain hash.
	fragments := []string{fmt.Sprintf("%s;", prefixFragment)}

	// Add in any comments.
	for _, c := range r.Comment {
		c = escapeComment(c)
		c = truncateComment(c)
		fragments = append(fragments, c)
	}
	cmt := strings.Join(fragments, " ")
	if cmt == "" {
		return nil
	}
	return &cmt
}

type Chain struct {
	Name  string
	Rules []Rule
}

func (c *Chain) RuleHashes(renderInner renderFunc, features *environment.Features) []string {
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
		ruleForHashing := rule.RenderAppend(c.Name, "HASH", renderInner, features)
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

// escapeComment replaces anything other than "safe" shell characters with an
// underscore (_).  This is a lossy conversion, but the expected use case
// for this stuff getting all the way to iptables are either
//   - hashes/IDs generated by higher layer systems
//   - comments on what the rules do
//
// which should be fine with this limitation.
// There just isn't a good way to escape this stuff in a way that iptables-restore
// will respect.  strconv.Quote() leaves actual quote characters in the output,
// which break iptables-restore.
func escapeComment(s string) string {
	return shellUnsafe.ReplaceAllString(s, "_")
}

const maxCommentLen = 256

func truncateComment(s string) string {
	if len(s) > maxCommentLen {
		return s[0:maxCommentLen]
	}
	return s
}
