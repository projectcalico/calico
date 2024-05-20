package generictables

import (
	"fmt"
	"strings"

	"github.com/projectcalico/calico/felix/environment"
	"sigs.k8s.io/knftables"
)

func NewNFTRenderer(hashCommentPrefix string) NFTRenderer {
	return &nftRenderer{
		hashCommentPrefix: hashCommentPrefix,
	}
}

type nftRenderer struct {
	hashCommentPrefix string
}

func (r *nftRenderer) Render(chain string, hash string, rule Rule, features *environment.Features) *knftables.Rule {
	return &knftables.Rule{
		Chain:   chain,
		Rule:    r.renderRule(&rule, features),
		Comment: r.comment(hash, rule),
	}
}

func (r *nftRenderer) RuleHashes(c *Chain, features *environment.Features) []string {
	rf := func(rule *Rule, chain string, features *environment.Features) string {
		return r.renderRule(rule, features)
	}
	return ruleHashes(c, rf, features)
}

func (r *nftRenderer) renderRule(rule *Rule, features *environment.Features) string {
	fragments := []string{}

	if rule.Match != nil {
		matchFragment := rule.Match.Render()
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
			fragments = append(fragments, actionFragment)
		}
	}

	inner := strings.Join(fragments, " ")
	if len(inner) == 0 {
		// If the rule is empty, it will cause nft to fail with a cryptic error message.
		// Instead, we'll just use a counter.
		return "counter"
	}
	return inner
}

func (r *nftRenderer) comment(hash string, rule Rule) *string {
	fragments := []string{}

	if r.hashCommentPrefix != "" && hash != "" {
		// Include the rule hash in the comment.
		fragments = append(fragments, fmt.Sprintf(`%s%s;`, r.hashCommentPrefix, hash))
	}

	// Add in any comments.
	for _, c := range rule.Comment {
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
