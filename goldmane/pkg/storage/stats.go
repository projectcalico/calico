package storage

import (
	"slices"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// StatisticsKey represents the key for a set of statistics.
type StatisticsKey struct {
	Namespace string
	Name      string
	Kind      proto.PolicyKind
	Tier      string
	Action    proto.Action
	RuleIndex int64
	Direction string
}

// policyID returns a statisticsKey that represents the policy, excluding any rule-specific information.
func (k *StatisticsKey) policyID() StatisticsKey {
	return StatisticsKey{
		Namespace: k.Namespace,
		Name:      k.Name,
		Kind:      k.Kind,
		Tier:      k.Tier,
	}
}

func (k *StatisticsKey) ToHit() *types.PolicyHit {
	return &types.PolicyHit{
		Namespace: k.Namespace,
		Name:      k.Name,
		Kind:      k.Kind,
		Tier:      k.Tier,
		Action:    k.Action,
		RuleIndex: k.RuleIndex,
	}
}

func (k *StatisticsKey) RuleDirection() proto.RuleDirection {
	switch k.Direction {
	case "ingress":
		return proto.RuleDirection_Ingress
	case "egress":
		return proto.RuleDirection_Egress
	default:
		return proto.RuleDirection_Any
	}
}

// policyStatistics is a struct that holds statistics for a policy, and for each rule within the policy.
type policyStatistics struct {
	statistics
	rules map[StatisticsKey]*statistics
}

// counts holds the packet and byte counts for a given context.
type counts struct {
	AllowedIn  int64
	AllowedOut int64
	DeniedIn   int64
	DeniedOut  int64
	PassedIn   int64
	PassedOut  int64
}

// statistics holds the statistics for a given context. This amy be for a particular time window,
// or for a particular policy within a time window, or for a particular policy rule within a policy.
type statistics struct {
	packets     counts
	bytes       counts
	connections counts
}

// add adds the statistics from a flow to the statistics object.
func (s *statistics) add(flow *types.Flow, action proto.Action) {
	switch action {
	case proto.Action_Allow:
		s.packets.AllowedIn += flow.PacketsIn
		s.packets.AllowedOut += flow.PacketsOut
		s.bytes.AllowedIn += flow.BytesIn
		s.bytes.AllowedOut += flow.BytesOut
		switch direction(flow.Key) {
		case "ingress":
			s.connections.AllowedIn += flow.NumConnectionsLive
		case "egress":
			s.connections.AllowedOut += flow.NumConnectionsLive
		}
	case proto.Action_Deny:
		s.packets.DeniedIn += flow.PacketsIn
		s.packets.DeniedOut += flow.PacketsOut
		s.bytes.DeniedIn += flow.BytesIn
		s.bytes.DeniedOut += flow.BytesOut
		switch direction(flow.Key) {
		case "ingress":
			s.connections.DeniedIn += flow.NumConnectionsLive
		case "egress":
			s.connections.DeniedOut += flow.NumConnectionsLive
		}
	case proto.Action_Pass:
		s.packets.PassedIn += flow.PacketsIn
		s.packets.PassedOut += flow.PacketsOut
		s.bytes.PassedIn += flow.BytesIn
		s.bytes.PassedOut += flow.BytesOut
		switch direction(flow.Key) {
		case "ingress":
			s.connections.PassedIn += flow.NumConnectionsLive
		case "egress":
			s.connections.PassedOut += flow.NumConnectionsLive
		}
	default:
		logrus.WithField("action", flow.Key.Action()).Error("Unknown action")
	}
}

// statisticsIndex is a struct that holds statistics for a set of policies.
type statisticsIndex struct {
	statistics
	policies map[StatisticsKey]*policyStatistics
}

func newStatisticsIndex() *statisticsIndex {
	return &statisticsIndex{
		policies: make(map[StatisticsKey]*policyStatistics),
	}
}

func (s *statisticsIndex) QueryStatistics(q *proto.StatisticsRequest) map[StatisticsKey]*counts {
	// Top level - group by policy or policy rule.
	// - If grouped by policy, we return one result per policy that matches the query.
	// - If grouped by policy rule, we return one result per policy rule that matches the query.
	results := make(map[StatisticsKey]*counts)

	for pk, ps := range s.policies {
		hit := pk.ToHit()

		if !matches(q, hit) {
			continue
		}

		switch q.GroupBy {
		case proto.StatisticsGroupBy_Policy:
			results[pk.policyID()] = s.retrieve(pk, &q.GroupBy, q.Type)
		case proto.StatisticsGroupBy_PolicyRule:
			// Need to drill down to the rules.
			for rk := range ps.rules {
				// Add in the rule-specific information.
				results[rk] = s.retrieve(rk, &q.GroupBy, q.Type)
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

	if !types.StringMatchMatches(q.PolicyMatch.Namespace, hit.Namespace) {
		return false
	}
	if !types.StringMatchMatches(q.PolicyMatch.Name, hit.Name) {
		return false
	}
	if q.PolicyMatch.Kind != proto.PolicyKind_KindUnspecified && q.PolicyMatch.Kind != hit.Kind {
		return false
	}
	if !types.StringMatchMatches(q.PolicyMatch.Tier, hit.Tier) {
		return false
	}
	if q.PolicyMatch.Action != proto.Action_ActionUnspecified && q.PolicyMatch.Action != hit.Action {
		return false
	}
	return true
}

// retrieve returns the requested statistic counts for a given policy hit.
func (s *statisticsIndex) retrieve(k StatisticsKey, groupBy *proto.StatisticsGroupBy, t proto.StatisticType) *counts {
	// Look up the policy in the map.
	ps, ok := s.policies[k.policyID()]
	if !ok {
		return nil
	}

	// If we're grouping by policy rule, we need to look up the rule in the policy.
	data := &ps.statistics
	if groupBy != nil && *groupBy == proto.StatisticsGroupBy_PolicyRule {
		rs, ok := ps.rules[k]
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
	case proto.StatisticType_LiveConnectionCount:
		return &data.connections
	default:
		logrus.WithField("type", t).Error("Unknown statistic type")
	}
	return nil
}

func direction(key *types.FlowKey) string {
	if key.Reporter() == proto.Reporter_Src {
		return "egress"
	}
	return "ingress"
}

// policyRule is one (policy, rule, action) contribution a flow makes to the statistics.
type policyRule struct {
	policyKey StatisticsKey
	ruleKey   StatisticsKey
	action    proto.Action
}

// toPolicyRules decodes the key's enforced and pending policy hits into the deduplicated rules
// they contribute to.
func toPolicyRules(k *types.FlowKey) []policyRule {
	trace := types.CachedPolicyTrace(k.Policies())
	dir := direction(k)

	// Pending hits may duplicate the enforced ones, which the rule check below drops.
	rules := make([]policyRule, 0, len(trace.EnforcedPolicies)+len(trace.PendingPolicies))
	for _, hits := range [2][]*proto.PolicyHit{trace.EnforcedPolicies, trace.PendingPolicies} {
		for _, hit := range hits {
			meta := hit
			if meta.Kind == proto.PolicyKind_EndOfTier {
				// For EndOfTier policies, use the policy that triggered the end of tier action to come into effect.
				// Note that the Action is still attached to the EndOfTier hit, not the trigger.
				meta = hit.Trigger
			}

			sk := StatisticsKey{
				Namespace: meta.Namespace,
				Name:      meta.Name,
				Kind:      meta.Kind,
				Tier:      meta.Tier,
				Action:    hit.Action,
				RuleIndex: meta.PolicyIndex,
				Direction: dir,
			}
			if slices.ContainsFunc(rules, func(r policyRule) bool { return r.ruleKey == sk }) {
				continue
			}
			rules = append(rules, policyRule{policyKey: sk.policyID(), ruleKey: sk, action: hit.Action})
		}
	}
	return rules
}

// AddFlow adds the flow's statistics to the index, and to each of the given rules and their
// policies.
func (s *statisticsIndex) AddFlow(flow *types.Flow, rules []policyRule) {
	// Add the stats from this Flow, aggregated across all the policies it matches.
	s.add(flow, flow.Key.Action())

	for i := range rules {
		rule := &rules[i]
		ps, ok := s.policies[rule.policyKey]
		if !ok {
			ps = &policyStatistics{rules: make(map[StatisticsKey]*statistics)}
			s.policies[rule.policyKey] = ps
		}

		// Add the Flow's stats to the policy.
		ps.add(flow, rule.action)

		// Add the Flow's stats to the rule within the policy.
		rs, ok := ps.rules[rule.ruleKey]
		if !ok {
			rs = &statistics{}
			ps.rules[rule.ruleKey] = rs
		}
		rs.add(flow, rule.action)
	}
}
