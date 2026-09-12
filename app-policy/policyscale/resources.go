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

// ResourceOptions control how a fixture is rendered as Calico resources.
type ResourceOptions struct {
	// Selector chooses the endpoints the policies apply to. Default: all().
	Selector string
	// SetLabelKey is the label that ties a GlobalNetworkSet to the rules that select it.
	// Default: policyscale.projectcalico.org/set.
	SetLabelKey string
	// TierOrder is the order of the generated tier(s); consecutive tiers count up from it.
	// Default 100.
	TierOrder float64
}

const (
	defaultSelector    = "all()"
	defaultSetLabelKey = "policyscale.projectcalico.org/set"
	defaultTierOrder   = 100
	apiVersion         = v3.GroupVersionCurrent
)

func (o *ResourceOptions) defaults() {
	if o.Selector == "" {
		o.Selector = defaultSelector
	}
	if o.SetLabelKey == "" {
		o.SetLabelKey = defaultSetLabelKey
	}
	if o.TierOrder == 0 {
		o.TierOrder = defaultTierOrder
	}
}

// Resources renders the fixture as the Calico resources that apply the same policy set on a
// cluster: one Tier per generated tier, one GlobalNetworkPolicy per policy (named tier.policy, in
// tier order), and one GlobalNetworkSet per IP set the store holds, labelled so that the rules'
// selectors pick it. Sets marked missing are rendered too: on a cluster nothing is ever "not
// found", and leaving them out would change the verdicts.
//
// Two departures from the proto the engine sees, both forced by the v3 API: a rule with ports
// carries protocol TCP, since ports require a protocol (every generated flow is TCP, so verdicts
// are unchanged), and policy names carry the tier prefix.
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
				gnp := &v3.GlobalNetworkPolicy{
					TypeMeta:   metav1.TypeMeta{Kind: v3.KindGlobalNetworkPolicy, APIVersion: apiVersion},
					ObjectMeta: metav1.ObjectMeta{Name: t.name + "." + p.name},
				}
				order := policyOrder
				policyOrder++
				gnp.Spec = v3.GlobalNetworkPolicySpec{
					Tier:     t.name,
					Order:    &order,
					Selector: opts.Selector,
				}
				rules := make([]v3.Rule, len(p.rules))
				for i, r := range p.rules {
					rules[i] = r.resource(opts.SetLabelKey)
				}
				if Direction(dir) == Egress {
					gnp.Spec.Types = []v3.PolicyType{v3.PolicyTypeEgress}
					gnp.Spec.Egress = rules
				} else {
					gnp.Spec.Types = []v3.PolicyType{v3.PolicyTypeIngress}
					gnp.Spec.Ingress = rules
				}
				out = append(out, gnp)
			}
		}
	}

	for _, id := range fx.setOrder {
		s := fx.sets[id]
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

func (r *ruleModel) resource(setLabelKey string) v3.Rule {
	rule := v3.Rule{Action: v3.Action(capitalise(r.action))}
	if len(r.dstPorts) > 0 {
		tcp := numorstring.ProtocolFromString("TCP")
		rule.Protocol = &tcp
		for _, p := range r.dstPorts {
			rule.Destination.Ports = append(rule.Destination.Ports, numorstring.SinglePort(uint16(p)))
		}
	}
	if r.dstNet.IsValid() {
		rule.Destination.Nets = []string{r.dstNet.String()}
	}
	rule.Source.Selector = setSelector(setLabelKey, r.srcSet)
	rule.Source.NotSelector = setSelector(setLabelKey, r.notSrcSet)
	rule.Destination.Selector = setSelector(setLabelKey, r.dstSet)
	rule.Destination.NotSelector = setSelector(setLabelKey, r.notDstSet)
	return rule
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
