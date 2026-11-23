// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policyscale

import (
	"fmt"
	"io"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// ResourceOptions control how a fixture is rendered as Calico resources. The zero value is safe
// to apply to a live cluster: the policies are staged, and apply only to endpoints labelled for
// them.
type ResourceOptions struct {
	// Selector chooses the endpoints the policies apply to. Default: TargetSelector.
	Selector string
	// SetLabelKey is the label that ties a GlobalNetworkSet to the rules that select it.
	// Default: policyscale.projectcalico.org/set.
	SetLabelKey string
	// TierOrder is the order of the generated tier(s); consecutive tiers count up from it.
	// Default 100.
	TierOrder float64
	// Enforced renders the fixture's enforced policies as GlobalNetworkPolicy. Otherwise every
	// policy is rendered as StagedGlobalNetworkPolicy: Felix still evaluates staged policies for
	// the pending verdict exactly as enforced ones, but a tier whose policies are all staged
	// programs no enforcement rules and ends in pass rather than drop, so the endpoints the set
	// selects keep working. A cluster then reports the staged kinds; see AsStaged.
	Enforced bool
}

const (
	// TargetLabel marks the endpoints a policy set rendered with the default selector applies to.
	TargetLabel = "policyscale.projectcalico.org/target"
	// TargetSelector is the default selector: endpoints labelled TargetLabel=true.
	TargetSelector = TargetLabel + " == 'true'"

	defaultSetLabelKey = "policyscale.projectcalico.org/set"
	defaultTierOrder   = 100
	apiVersion         = v3.GroupVersionCurrent
)

func (o *ResourceOptions) defaults() {
	if o.Selector == "" {
		o.Selector = TargetSelector
	}
	if o.SetLabelKey == "" {
		o.SetLabelKey = defaultSetLabelKey
	}
	if o.TierOrder == 0 {
		o.TierOrder = defaultTierOrder
	}
}

// Resources renders the fixture as the Calico resources that apply the same policy set on a
// cluster: one Tier per generated tier, one policy per policy of the fixture, under the same name
// and in tier order, and the GlobalNetworkSets that hold the IP sets' members, labelled so that
// the rules' selectors pick them. Sets marked missing are rendered too: on a cluster nothing is
// ever "not found", and leaving them out would change the verdicts.
func (fx *Fixture) Resources(opts ResourceOptions) []runtime.Object {
	opts.defaults()
	var out []runtime.Object

	for i, t := range fx.tiers {
		order := opts.TierOrder + float64(i)
		action := v3.Action(t.defaultAction)
		out = append(out, &v3.Tier{
			TypeMeta:   metav1.TypeMeta{Kind: v3.KindTier, APIVersion: apiVersion},
			ObjectMeta: metav1.ObjectMeta{Name: t.name},
			Spec:       v3.TierSpec{Order: &order, DefaultAction: &action},
		})
	}

	for _, t := range fx.tiers {
		policyOrder := float64(0)
		for dir, policies := range t.policies {
			for _, p := range policies {
				name := p.name
				order := policyOrder
				policyOrder++
				rules := make([]v3.Rule, len(p.rules))
				for i, r := range p.rules {
					rules[i] = fx.ruleResource(r, opts.SetLabelKey)
				}
				var types []v3.PolicyType
				var ingress, egress []v3.Rule
				if Direction(dir) == Egress {
					types, egress = []v3.PolicyType{v3.PolicyTypeEgress}, rules
				} else {
					types, ingress = []v3.PolicyType{v3.PolicyTypeIngress}, rules
				}
				if p.staged || !opts.Enforced {
					out = append(out, &v3.StagedGlobalNetworkPolicy{
						TypeMeta:   metav1.TypeMeta{Kind: v3.KindStagedGlobalNetworkPolicy, APIVersion: apiVersion},
						ObjectMeta: metav1.ObjectMeta{Name: name},
						Spec: v3.StagedGlobalNetworkPolicySpec{
							StagedAction: v3.StagedActionSet,
							Tier:         t.name,
							Order:        &order,
							Selector:     opts.Selector,
							Types:        types,
							Ingress:      ingress,
							Egress:       egress,
						},
					})
					continue
				}
				out = append(out, &v3.GlobalNetworkPolicy{
					TypeMeta:   metav1.TypeMeta{Kind: v3.KindGlobalNetworkPolicy, APIVersion: apiVersion},
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: v3.GlobalNetworkPolicySpec{
						Tier:     t.name,
						Order:    &order,
						Selector: opts.Selector,
						Types:    types,
						Ingress:  ingress,
						Egress:   egress,
					},
				})
			}
		}
	}

	for _, id := range fx.setOrder {
		s := fx.sets[id]
		if s.isIPPort() {
			// Felix makes these from named ports and services, which are rendered on the rules.
			continue
		}
		out = append(out, &v3.GlobalNetworkSet{
			TypeMeta: metav1.TypeMeta{Kind: v3.KindGlobalNetworkSet, APIVersion: apiVersion},
			ObjectMeta: metav1.ObjectMeta{
				Name:   id,
				Labels: map[string]string{opts.SetLabelKey: id},
			},
			Spec: v3.GlobalNetworkSetSpec{Nets: s.members},
		})
	}
	return out
}

func (fx *Fixture) ruleResource(r *ruleModel, setLabelKey string) v3.Rule {
	rule := v3.Rule{Action: v3.Action(capitalise(r.action))}
	rule.Protocol = r.protocol.resource()
	rule.NotProtocol = r.notProtocol.resource()
	if r.ipVersion != 0 {
		v := r.ipVersion
		rule.IPVersion = &v
	}
	rule.ICMP = r.icmp.resource()
	rule.NotICMP = r.notICMP.resource()
	for _, p := range r.dstPorts {
		rule.Destination.Ports = append(rule.Destination.Ports, numorstring.SinglePort(uint16(p)))
	}
	rule.Destination.Ports = append(rule.Destination.Ports, portResources(r.dstPortRanges)...)
	rule.Source.Ports = portResources(r.srcPortRanges)
	rule.Destination.NotPorts = portResources(r.notDstPortRanges)
	if np, ok := fx.namedPortBySet[r.dstNamedPortSet]; ok {
		rule.Destination.Ports = append(rule.Destination.Ports, namedPort(np.Name))
	}
	if np, ok := fx.namedPortBySet[r.notDstNamedPortSet]; ok {
		rule.Destination.NotPorts = append(rule.Destination.NotPorts, namedPort(np.Name))
	}
	if svc, ok := fx.serviceBySet[r.dstServiceSet]; ok {
		rule.Destination.Services = &v3.ServiceMatch{Name: svc.Name, Namespace: svc.Namespace}
	}
	if r.dstNet.IsValid() {
		rule.Destination.Nets = []string{r.dstNet.String()}
	}
	rule.Destination.Nets = append(rule.Destination.Nets, prefixStrings(r.dstNets)...)
	rule.Destination.NotNets = prefixStrings(r.notDstNets)
	rule.Source.Nets = prefixStrings(r.srcNets)
	rule.Source.NotNets = prefixStrings(r.notSrcNets)
	rule.Source.Selector = setSelector(setLabelKey, r.srcSet)
	rule.Source.NotSelector = setSelector(setLabelKey, r.notSrcSet)
	rule.Destination.Selector = setSelector(setLabelKey, r.dstSet)
	rule.Destination.NotSelector = setSelector(setLabelKey, r.notDstSet)
	return rule
}

func (p *protocolModel) resource() *numorstring.Protocol {
	if p == nil {
		return nil
	}
	var out numorstring.Protocol
	if p.name != "" {
		out = numorstring.ProtocolFromString(p.name)
	} else {
		out = numorstring.ProtocolFromInt(uint8(p.number))
	}
	return &out
}

func (m *icmpModel) resource() *v3.ICMPFields {
	if m == nil {
		return nil
	}
	typ := m.typ
	f := &v3.ICMPFields{Type: &typ}
	if m.hasCode {
		code := m.code
		f.Code = &code
	}
	return f
}

func portResources(ranges []portRange) []numorstring.Port {
	var out []numorstring.Port
	for _, r := range ranges {
		if r.first == r.last {
			out = append(out, numorstring.SinglePort(uint16(r.first)))
			continue
		}
		p, err := numorstring.PortFromRange(uint16(r.first), uint16(r.last))
		if err != nil {
			panic(err)
		}
		out = append(out, p)
	}
	return out
}

func namedPort(name string) numorstring.Port {
	p, err := numorstring.NamedPort(name)
	if err != nil {
		panic(err)
	}
	return p
}

func setSelector(key, setID string) string {
	if setID == "" {
		return ""
	}
	return fmt.Sprintf("%s == '%s'", key, setID)
}

func capitalise(action string) string {
	if action == "" {
		return ""
	}
	return string(action[0]-'a'+'A') + action[1:]
}

// AsStaged returns the trace as a cluster reports it when the policies are rendered staged: with
// the staged kind of every policy.
func AsStaged(trace []Verdict) []Verdict {
	out := make([]Verdict, len(trace))
	for i, v := range trace {
		if k, ok := stagedKinds[v.Kind]; ok {
			v.Kind = k
		}
		out[i] = v
	}
	return out
}

var stagedKinds = map[string]string{
	v3.KindGlobalNetworkPolicy: v3.KindStagedGlobalNetworkPolicy,
	v3.KindNetworkPolicy:       v3.KindStagedNetworkPolicy,
}

// WriteYAML writes Resources as a multi-document YAML stream, ready for kubectl apply -f.
func (fx *Fixture) WriteYAML(w io.Writer, opts ResourceOptions) error {
	for i, obj := range fx.Resources(opts) {
		if i > 0 {
			if _, err := io.WriteString(w, "---\n"); err != nil {
				return err
			}
		}
		b, err := yaml.Marshal(obj)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
}
