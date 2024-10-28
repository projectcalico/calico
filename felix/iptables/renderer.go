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

package iptables

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
)

const maxIptablesCommentLength = 256

var shellUnsafe = regexp.MustCompile(`[^\w @%+=:,./-]`)

type IptablesRenderer interface {
	generictables.RuleHasher
	RenderAppend(rule *generictables.Rule, chainName, hash string, features *environment.Features) string
	RenderInsert(rule *generictables.Rule, chainName, hash string, features *environment.Features) string
	RenderInsertAtRuleNumber(rule *generictables.Rule, chainName string, ruleNum int, hash string, features *environment.Features) string
	RenderReplace(rule *generictables.Rule, chainName string, ruleNum int, hash string, features *environment.Features) string
}

func NewIptablesRenderer(hashCommentPrefix string) IptablesRenderer {
	return &iptablesRenderer{
		hashCommentPrefix: hashCommentPrefix,
	}
}

type iptablesRenderer struct {
	hashCommentPrefix string
}

func (i *iptablesRenderer) RenderAppend(r *generictables.Rule, chainName string, hash string, features *environment.Features) string {
	fragments := make([]string, 0, 6)
	fragments = append(fragments, "-A", chainName)
	hashCommentFragment := i.commentFrag(hash)
	return i.renderInner(fragments, hashCommentFragment, r.Match, r.Action, r.Comment, features)
}

func (i *iptablesRenderer) RenderInsert(r *generictables.Rule, chainName string, hash string, features *environment.Features) string {
	fragments := make([]string, 0, 6)
	fragments = append(fragments, "-I", chainName)
	hashCommentFragment := i.commentFrag(hash)
	return i.renderInner(fragments, hashCommentFragment, r.Match, r.Action, r.Comment, features)
}

func (i *iptablesRenderer) RenderInsertAtRuleNumber(r *generictables.Rule, chainName string, ruleNum int, hash string, features *environment.Features) string {
	fragments := make([]string, 0, 7)
	fragments = append(fragments, "-I", chainName, fmt.Sprintf("%d", ruleNum))
	hashCommentFragment := i.commentFrag(hash)
	return i.renderInner(fragments, hashCommentFragment, r.Match, r.Action, r.Comment, features)
}

func (i *iptablesRenderer) RenderReplace(r *generictables.Rule, chainName string, ruleNum int, hash string, features *environment.Features) string {
	fragments := make([]string, 0, 7)
	fragments = append(fragments, "-R", chainName, fmt.Sprintf("%d", ruleNum))
	hashCommentFragment := i.commentFrag(hash)
	return i.renderInner(fragments, hashCommentFragment, r.Match, r.Action, r.Comment, features)
}

func (i *iptablesRenderer) RuleHashes(c *generictables.Chain, features *environment.Features) []string {
	ruleFn := func(r *generictables.Rule, chain string, features *environment.Features) string {
		return i.RenderAppend(r, chain, "HASH", features)
	}
	return generictables.RuleHashes(c, ruleFn, features)
}

func (i *iptablesRenderer) commentFrag(hash string) string {
	if hash == "HASH" {
		// Special case for generating chain hashes, which don't include the comment fragment.
		return hash
	} else if hash == "" {
		// If the hash is empty, we don't generate a comment.
		return ""
	}
	return fmt.Sprintf(`-m comment --comment "%s%s"`, i.hashCommentPrefix, hash)
}

func (i *iptablesRenderer) renderInner(fragments []string, hashCommentFragment string, match generictables.MatchCriteria, action generictables.Action, comment []string, features *environment.Features) string {
	if hashCommentFragment != "" {
		fragments = append(fragments, hashCommentFragment)
	}
	for _, c := range comment {
		c = escapeComment(c)
		c = i.truncateComment(c)
		commentFragment := fmt.Sprintf("-m comment --comment \"%s\"", c)
		fragments = append(fragments, commentFragment)
	}
	if match != nil {
		matchFragment := match.Render()
		if matchFragment != "" {
			fragments = append(fragments, matchFragment)
		}
	}
	if action != nil {
		actionFragment := action.ToFragment(features)
		if actionFragment != "" {
			fragments = append(fragments, actionFragment)
		}
	}
	return strings.Join(fragments, " ")
}

func (i *iptablesRenderer) truncateComment(s string) string {
	if len(s) > maxIptablesCommentLength {
		return s[0:maxIptablesCommentLength]
	}
	return s
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
