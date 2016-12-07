package rules

import "github.com/projectcalico/felix/go/felix/iptables"

func (r *ruleRenderer) NATOutgoingChain(active bool, ipVersion uint8) *iptables.Chain {
	var rules []iptables.Rule
	if active {
		ipConf := r.ipSetConfig(ipVersion)
		allIPsSetName := ipConf.NameForMainIPSet(NATOutgoingAllIPsSetID)
		masqIPsSetName := ipConf.NameForMainIPSet(NATOutgoingMasqIPsSetID)
		rules = []iptables.Rule{
			{
				Action: iptables.MasqAction{},
				Match: iptables.Match().
					SourceIPSet(masqIPsSetName).
					NotDestIPSet(allIPsSetName),
			},
		}
	}
	return &iptables.Chain{
		Name: NATOutgoingChainName,
		Rules: rules,
	}
}
