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

package nftables

import (
	"fmt"
	"regexp"
	"strings"

	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
)

var shellUnsafe = regexp.MustCompile(`[^\w @%+=:,./-]`)

type NFTRenderer interface {
	generictables.RuleHasher
	Render(chain string, hash string, rule generictables.Rule, features *environment.Features) *knftables.Rule
}

func NewNFTRenderer(hashCommentPrefix string, ipv uint8) NFTRenderer {
	return &nftRenderer{
		ipv:               ipv,
		hashCommentPrefix: hashCommentPrefix,
	}
}

type nftRenderer struct {
	ipv               uint8
	hashCommentPrefix string
}

func (r *nftRenderer) Render(chain string, hash string, rule generictables.Rule, features *environment.Features) *knftables.Rule {
	return &knftables.Rule{
		Chain:   chain,
		Rule:    r.renderRule(&rule, features),
		Comment: r.comment(hash, rule),
	}
}

func (r *nftRenderer) RuleHashes(c *generictables.Chain, features *environment.Features) []string {
	rf := func(rule *generictables.Rule, chain string, features *environment.Features) string {
		return r.renderRule(rule, features)
	}
	return generictables.RuleHashes(c, rf, features)
}

func (r *nftRenderer) renderRule(rule *generictables.Rule, features *environment.Features) string {
	fragments := []string{}

	if rule.Match != nil {
		matchFragment := rule.Match.(NFTMatchCriteria).IPVersion(r.ipv).Render()
		if matchFragment != "" {
			fragments = append(fragments, matchFragment)
		}
	}

	if rule.Action != nil {
		// Include a counter action on all rules.
		fragments = append(fragments, "counter")

		// Render other actions.
		actionFragment := rule.Action.ToFragment(features)
		if actionFragment != "" {
			fragments = append(fragments, insertIPVersion(actionFragment, r.ipv))
		}
	}

	inner := strings.Join(fragments, " ")
	if len(inner) == 0 {
		// If the rule is empty, it will cause nft to fail with a cryptic error message.
		// Instead, we'll just use a continue action to make the rule a no-op.
		return "continue"
	}
	return inner
}

func (r *nftRenderer) comment(hash string, rule generictables.Rule) *string {
	fragments := []string{}

	if r.hashCommentPrefix != "" && hash != "" {
		// Include the rule hash in the comment.
		fragments = append(fragments, fmt.Sprintf(`%s%s;`, r.hashCommentPrefix, hash))
	}

	// Add in any comments. Each individual comment must be small enough such that the
	// total comment is less than 128 characters.
	if len(rule.Comment) > 0 {
		maxPerComment := (knftables.CommentLengthMax - len(strings.Join(fragments, " "))) / len(rule.Comment)
		for _, c := range rule.Comment {
			c = escapeComment(c)
			c = r.truncateComment(c, maxPerComment)
			fragments = append(fragments, c)
		}
	}

	// Truncate the entire comment if needed.
	cmt := r.truncateComment(strings.Join(fragments, " "), knftables.CommentLengthMax)
	if cmt == "" {
		return nil
	}
	return &cmt
}

func (r *nftRenderer) truncateComment(s string, size int) string {
	if len(s) > size {
		return s[0:size]
	}
	return s
}

func escapeComment(s string) string {
	return shellUnsafe.ReplaceAllString(s, "_")
}
