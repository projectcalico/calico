package bucketing

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// policyKey is a local representation of the identifying fields for a policy.
// It excludes rule identifying information.
type policyKey struct {
	Namespace string
	Name      string
	Kind      proto.PolicyKind
	Tier      string
	Action    string
}

func (k *policyKey) toHit() types.PolicyHit {
	return types.PolicyHit{
		Namespace: k.Namespace,
		Name:      k.Name,
		Kind:      k.Kind,
		Tier:      k.Tier,
		Action:    k.Action,
	}
}

func key(hit *types.PolicyHit) policyKey {
	return policyKey{
		Namespace: hit.Namespace,
		Name:      hit.Name,
		Kind:      hit.Kind,
		Tier:      hit.Tier,
		Action:    hit.Action,
	}
}

// ruleKey is a local representation of the identifying fields for a policy rule, given the
// context of a policy. It excludes policy identifying information.
type ruleKey struct {
	Index int64
}

// policyStatistics is a struct that holds statistics for a policy, and for each rule within the policy.
type policyStatistics struct {
	statistics
	rules map[ruleKey]*statistics
}

// counts holds the packet and byte counts for a given context.
type counts struct {
	AllowedIn  int64
	AllowedOut int64
	DeniedIn   int64
	DeniedOut  int64
}

// statistics holds the statistics for a given context. This amy be for a particular time window,
// or for a particular policy within a time window, or for a particular policy rule within a policy.
type statistics struct {
	packets counts
	bytes   counts
}

// add adds the statistics from a flow to the statistics object.
func (s *statistics) add(flow *types.Flow) {
	if flow.Key.Action == "allow" {
		s.packets.AllowedIn += flow.PacketsIn
		s.packets.AllowedOut += flow.PacketsOut
		s.bytes.AllowedIn += flow.BytesIn
		s.bytes.AllowedOut += flow.BytesOut
	} else if flow.Key.Action == "deny" {
		s.packets.DeniedIn += flow.PacketsIn
		s.packets.DeniedOut += flow.PacketsOut
		s.bytes.DeniedIn += flow.BytesIn
		s.bytes.DeniedOut += flow.BytesOut
	} else {
		logrus.WithField("action", flow.Key.Action).Error("Unknown action")
	}
}

// statisticsIndex is a struct that holds statistics for a set of policies.
type statisticsIndex struct {
	statistics
	policies map[policyKey]*policyStatistics
}

func newStatisticsIndex() *statisticsIndex {
	return &statisticsIndex{
		policies: make(map[policyKey]*policyStatistics),
	}
}

func (s *statisticsIndex) QueryStatistics(q *proto.StatisticsRequest) map[types.PolicyHit]*counts {
	// Top level - group by policy or policy rule.
	// - If grouped by policy, we return one result per policy that matches the query.
	// - If grouped by policy rule, we return one result per policy rule that matches the query.
	results := make(map[types.PolicyHit]*counts)

	for pk, ps := range s.policies {
		hit := pk.toHit()

		if !matches(q, &hit) {
			continue
		}

		switch q.GroupBy {
		case proto.GroupBy_Policy:
			results[hit] = s.retrieve(&hit, &q.GroupBy, q.Type)
		case proto.GroupBy_PolicyRule:
			// Need to drill down to the rules.
			for rk := range ps.rules {
				// Copy the hit and set the rule index.
				h := hit
				h.RuleIndex = rk.Index
				results[h] = s.retrieve(&h, &q.GroupBy, q.Type)
			}
		default:
			logrus.WithField("group_by", q.GroupBy).Error("Unknown group by")
			return nil
		}
	}
	return results
}

func matches(q *proto.StatisticsRequest, hit *types.PolicyHit) bool {
	if q.PolicyMatch == nil {
		// No match criteria, everything matches.
		return true
	}

	if q.PolicyMatch.Namespace != "" && q.PolicyMatch.Namespace != hit.Namespace {
		return false
	}
	if q.PolicyMatch.Name != "" && q.PolicyMatch.Name != hit.Name {
		return false
	}
	if q.PolicyMatch.Kind != proto.PolicyKind_KindUnspecified && q.PolicyMatch.Kind != hit.Kind {
		return false
	}
	if q.PolicyMatch.Tier != "" && q.PolicyMatch.Tier != hit.Tier {
		return false
	}
	if q.PolicyMatch.Action != "" && q.PolicyMatch.Action != hit.Action {
		return false
	}
	return true
}

// retrieve returns the requested statistic counts for a given policy hit.
func (s *statisticsIndex) retrieve(p *types.PolicyHit, groupBy *proto.GroupBy, t proto.StatisticType) *counts {
	// Look up the policy in the map.
	ps, ok := s.policies[key(p)]
	if !ok {
		return nil
	}

	// If we're grouping by policy rule, we need to look up the rule in the policy.
	data := &ps.statistics
	if groupBy != nil && *groupBy == proto.GroupBy_PolicyRule {
		rk := ruleKey{Index: p.RuleIndex}
		rs, ok := ps.rules[rk]
		if !ok {
			return nil
		}
		data = rs
	}

	// Return the requested statistic.
	switch t {
	case proto.StatisticType_PacketCount:
		return &data.packets
	case proto.StatisticType_ByteCount:
		return &data.bytes
	default:
		logrus.WithField("type", t).Error("Unknown statistic type")
	}
	return nil
}

func (s *statisticsIndex) AddFlow(flow *types.Flow) {
	logrus.WithField("flow", flow).Debug("Adding flow to bucket statistics index")

	// Add the stats from this Flow, aggregated across all the policies it matches.
	s.add(flow)

	// For each policy in the flow, add the stats to the policy. The PolicyStatistics object
	// is responsible for tracking the stats for each rule in the policy.
	rules := types.FlowLogPolicyToProto(flow.Key.Policies).EnforcedPolicies

	// Build a map of policies to rules within the policy hit by this Flow. We want to add this Flow's
	// statistics contribution once to each Policy, and once to each Rule within the Policy.
	polToRules := make(map[policyKey][]ruleKey)
	for _, rule := range rules {
		// Build a key for the policy, excluding per-rule information.
		pk := policyKey{
			Namespace: rule.Namespace,
			Name:      rule.Name,
			Kind:      rule.Kind,
			Tier:      rule.Tier,
			Action:    rule.Action,
		}
		polToRules[pk] = append(polToRules[pk], ruleKey{Index: rule.PolicyIndex})
	}

	// For each Policy, add this Flow to the PolicyStatistics object.
	for pk, rules := range polToRules {
		logrus.WithField("policy", pk).Debug("Adding flow to policy")
		ps, ok := s.policies[pk]
		if !ok {
			ps = &policyStatistics{rules: make(map[ruleKey]*statistics)}
			s.policies[pk] = ps
		}

		// Add the Flow's stats once for the Policy.
		ps.add(flow)

		// Add the Flow's stats to each rule within the policy as well.
		for _, rk := range rules {
			rs, ok := ps.rules[rk]
			if !ok {
				rs = &statistics{}
				ps.rules[rk] = rs
			}

			logrus.WithField("rule", rk).Debug("Adding flow to rule")
			rs.add(flow)
		}
	}
}
