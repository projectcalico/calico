package bucketing

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
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
		switch direction(flow) {
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
		switch direction(flow) {
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
		switch direction(flow) {
		case "ingress":
			s.connections.PassedIn += flow.NumConnectionsLive
		case "egress":
			s.connections.PassedOut += flow.NumConnectionsLive
		}
	default:
		logrus.WithField("action", flow.Key.Action).Error("Unknown action")
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

func direction(flow *types.Flow) string {
	if flow.Key.Reporter == proto.Reporter_Src {
		return "egress"
	}
	return "ingress"
}

func (s *statisticsIndex) AddFlow(flow *types.Flow) {
	logrus.WithField("flow", flow).Debug("Adding flow to statistics index")

	// Add the stats from this Flow, aggregated across all the policies it matches.
	s.add(flow, flow.Key.Action)

	// For each policy in the flow, add the stats to the policy. The PolicyStatistics object
	// is responsible for tracking the stats for each rule in the policy.
	rules := types.FlowLogPolicyToProto(flow.Key.Policies).EnforcedPolicies

	// Add pending policies as well - these may contain duplicates of the enforced rules, but
	// we deduplicate them in the loop below.
	rules = append(rules, types.FlowLogPolicyToProto(flow.Key.Policies).PendingPolicies...)

	// Build a map of policies to rules within the policy hit by this Flow. We want to add this Flow's
	// statistics contribution once to each Policy, and once to each Rule within the Policy.
	polToRules := make(map[StatisticsKey]map[StatisticsKey]proto.Action)
	for _, rule := range rules {
		// Build a key for the policy, excluding per-rule information.
		sk := StatisticsKey{
			Namespace: rule.Namespace,
			Name:      rule.Name,
			Kind:      rule.Kind,
			Tier:      rule.Tier,
			Action:    rule.Action,
			RuleIndex: rule.PolicyIndex,
			Direction: direction(flow),
		}
		pk := sk.policyID()
		if _, ok := polToRules[pk]; !ok {
			polToRules[pk] = make(map[StatisticsKey]proto.Action)
		}
		if action, ok := polToRules[pk][sk]; ok && action != rule.Action {
			logrus.WithFields(logrus.Fields{
				"policy":      sk,
				"conflicting": rule.Action,
				"selected":    action,
			}).Warnf("Policy rule has conflicting actions, using the first action")
		} else {
			polToRules[pk][sk] = rule.Action
		}
	}

	// For each Policy, add this Flow to the PolicyStatistics object.
	for pk, rules := range polToRules {
		logrus.WithField("policy", pk).Debug("Adding flow statistics to policy")
		ps, ok := s.policies[pk]
		if !ok {
			ps = &policyStatistics{rules: make(map[StatisticsKey]*statistics)}
			s.policies[pk] = ps
		}

		// Add the Flow's stats to each rule within the policy as well.
		for k, action := range rules {
			// Add the Flow's stats the the policy.
			ps.add(flow, action)

			// Add the Flow's stats to the rule within the policy.
			rs, ok := ps.rules[k]
			if !ok {
				rs = &statistics{}
				ps.rules[k] = rs
			}

			logrus.WithField("rule", k).Debug("Adding flow statistics to rule")
			rs.add(flow, action)
		}
	}
}
