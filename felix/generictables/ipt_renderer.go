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
	"fmt"
	"strings"

	"github.com/projectcalico/calico/felix/environment"
)

func NewIptablesRenderer(hashCommentPrefix string) IptablesRenderer {
	return &iptablesRenderer{
		hashCommentPrefix: hashCommentPrefix,
	}
}

type iptablesRenderer struct {
	hashCommentPrefix string
}

func (i *iptablesRenderer) RenderAppend(r *Rule, chainName string, hash string, features *environment.Features) string {
	fragments := make([]string, 0, 6)
	fragments = append(fragments, "-A", chainName)
	hashCommentFragment := i.commentFrag(hash)
	return i.renderInner(fragments, hashCommentFragment, r.Match, r.Action, r.Comment, features)
}

func (i *iptablesRenderer) RenderInsert(r *Rule, chainName string, hash string, features *environment.Features) string {
	fragments := make([]string, 0, 6)
	fragments = append(fragments, "-I", chainName)
	hashCommentFragment := i.commentFrag(hash)
	return i.renderInner(fragments, hashCommentFragment, r.Match, r.Action, r.Comment, features)
}

func (i *iptablesRenderer) RenderInsertAtRuleNumber(r *Rule, chainName string, ruleNum int, hash string, features *environment.Features) string {
	fragments := make([]string, 0, 7)
	fragments = append(fragments, "-I", chainName, fmt.Sprintf("%d", ruleNum))
	hashCommentFragment := i.commentFrag(hash)
	return i.renderInner(fragments, hashCommentFragment, r.Match, r.Action, r.Comment, features)
}

func (i *iptablesRenderer) RenderReplace(r *Rule, chainName string, ruleNum int, hash string, features *environment.Features) string {
	fragments := make([]string, 0, 7)
	fragments = append(fragments, "-R", chainName, fmt.Sprintf("%d", ruleNum))
	hashCommentFragment := i.commentFrag(hash)
	return i.renderInner(fragments, hashCommentFragment, r.Match, r.Action, r.Comment, features)
}

func (i *iptablesRenderer) RuleHashes(c *Chain, features *environment.Features) []string {
	ruleFn := func(r *Rule, chain string, features *environment.Features) string {
		return i.RenderAppend(r, chain, "HASH", features)
	}
	return ruleHashes(c, ruleFn, features)
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

func (i *iptablesRenderer) renderInner(fragments []string, hashCommentFragment string, match MatchCriteria, action Action, comment []string, features *environment.Features) string {
	if hashCommentFragment != "" {
		fragments = append(fragments, hashCommentFragment)
	}
	for _, c := range comment {
		c = escapeComment(c)
		c = truncateComment(c)
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
