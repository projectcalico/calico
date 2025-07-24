package rules

import (
	"github.com/projectcalico/calico/felix/dataplane/linux/qos"
	"github.com/projectcalico/calico/felix/generictables"
)

func (r *DefaultRuleRenderer) EgressQoSPolicyChain(policies []qos.Policy) *generictables.Chain {
	var rules []generictables.Rule

	for _, p := range policies {
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch().SourceNet(p.SrcAddrs),
			Action: r.DSCP(20),
		})
	}

	return &generictables.Chain{
		Name:  ChainQosPolicy,
		Rules: rules,
	}
}
