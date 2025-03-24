// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package types

import (
	"encoding/json"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/proto"
)

type FlowKeySource struct {
	SourceName      string
	SourceNamespace string
	SourceType      proto.EndpointType
}

type FlowKeyDestination struct {
	DestName             string
	DestNamespace        string
	DestType             proto.EndpointType
	DestPort             int64
	DestServiceName      string
	DestServiceNamespace string
	DestServicePortName  string
	DestServicePort      int64
}

type FlowKeyMeta struct {
	Proto    string
	Reporter proto.Reporter
	Action   proto.Action
}

// FlowKey is a unique key for a flow. It matches the protobuf API exactly. Unfortunately,
// we cannot use the protobuf API structures as map keys due to private fields that are inserted
// by the protobuf Go code generation. So we need a copy of the struct here.
//
// This struct should encapsulate the full set of fields avaialble on proto.FlowKey structure, but without the private fields.
type FlowKey struct {
	Source      unique.Handle[FlowKeySource]
	Destination unique.Handle[FlowKeyDestination]
	Meta        unique.Handle[FlowKeyMeta]
	Policies    unique.Handle[PolicyTrace]
}

func (k *FlowKey) Action() proto.Action {
	return k.Meta.Value().Action
}

func (k *FlowKey) Reporter() proto.Reporter {
	return k.Meta.Value().Reporter
}

func (k *FlowKey) Proto() string {
	return k.Meta.Value().Proto
}

func (k *FlowKey) SourceName() string {
	return k.Source.Value().SourceName
}

func (k *FlowKey) SourceNamespace() string {
	return k.Source.Value().SourceNamespace
}

func (k *FlowKey) DestName() string {
	return k.Destination.Value().DestName
}

func (k *FlowKey) DestNamespace() string {
	return k.Destination.Value().DestNamespace
}

func (k *FlowKey) DestPort() int64 {
	return k.Destination.Value().DestPort
}

// This struct should be an exact copy of the proto.Flow structure, but without the private fields.
type Flow struct {
	Key                     *FlowKey
	StartTime               int64
	EndTime                 int64
	SourceLabels            []string
	DestLabels              []string
	PacketsIn               int64
	PacketsOut              int64
	BytesIn                 int64
	BytesOut                int64
	NumConnectionsStarted   int64
	NumConnectionsCompleted int64
	NumConnectionsLive      int64
}

type PolicyTrace struct {
	EnforcedPolicies string
	PendingPolicies  string
}

type PolicyHit struct {
	Kind        proto.PolicyKind
	Namespace   string
	Name        string
	Tier        string
	Action      proto.Action
	PolicyIndex int64
	RuleIndex   int64
}

func ProtoToPolicyHit(p *proto.PolicyHit) *PolicyHit {
	return &PolicyHit{
		Kind:        p.Kind,
		Namespace:   p.Namespace,
		Name:        p.Name,
		Tier:        p.Tier,
		Action:      p.Action,
		PolicyIndex: p.PolicyIndex,
		RuleIndex:   p.RuleIndex,
	}
}

func PolicyHitToProto(p *PolicyHit) *proto.PolicyHit {
	return &proto.PolicyHit{
		Kind:        p.Kind,
		Namespace:   p.Namespace,
		Name:        p.Name,
		Tier:        p.Tier,
		Action:      p.Action,
		PolicyIndex: p.PolicyIndex,
		RuleIndex:   p.RuleIndex,
	}
}

func ProtoToFlow(p *proto.Flow) *Flow {
	return &Flow{
		Key:                     ProtoToFlowKey(p.Key),
		StartTime:               p.StartTime,
		EndTime:                 p.EndTime,
		SourceLabels:            p.SourceLabels,
		DestLabels:              p.DestLabels,
		PacketsIn:               p.PacketsIn,
		PacketsOut:              p.PacketsOut,
		BytesIn:                 p.BytesIn,
		BytesOut:                p.BytesOut,
		NumConnectionsStarted:   p.NumConnectionsStarted,
		NumConnectionsCompleted: p.NumConnectionsCompleted,
		NumConnectionsLive:      p.NumConnectionsLive,
	}
}

func ProtoToFlowKey(p *proto.FlowKey) *FlowKey {
	if p == nil {
		return nil
	}
	return &FlowKey{
		Source: unique.Make(FlowKeySource{
			SourceName:      p.SourceName,
			SourceNamespace: p.SourceNamespace,
			SourceType:      p.SourceType,
		}),
		Destination: unique.Make(FlowKeyDestination{
			DestName:             p.DestName,
			DestNamespace:        p.DestNamespace,
			DestType:             p.DestType,
			DestPort:             p.DestPort,
			DestServiceName:      p.DestServiceName,
			DestServiceNamespace: p.DestServiceNamespace,
			DestServicePortName:  p.DestServicePortName,
			DestServicePort:      p.DestServicePort,
		}),
		Meta: unique.Make(FlowKeyMeta{
			Proto:    p.Proto,
			Reporter: p.Reporter,
			Action:   p.Action,
		}),
		Policies: ProtoToFlowLogPolicy(p.Policies),
	}
}

func ProtoToFlowLogPolicy(p *proto.PolicyTrace) unique.Handle[PolicyTrace] {
	var ep, pp string
	if p != nil {
		if len(p.EnforcedPolicies) > 0 {
			epb, err := json.Marshal(p.EnforcedPolicies)
			if err != nil {
				logrus.WithError(err).Fatal("Failed to marshal enforced policies")
			}
			ep = string(epb)
		}

		if len(p.PendingPolicies) > 0 {
			ppb, err := json.Marshal(p.PendingPolicies)
			if err != nil {
				logrus.WithError(err).Fatal("Failed to marshal pending policies")
			}
			pp = string(ppb)
		}
	}
	flp := PolicyTrace{
		EnforcedPolicies: ep,
		PendingPolicies:  pp,
	}
	return unique.Make(flp)
}

func FlowToProto(f *Flow) *proto.Flow {
	return &proto.Flow{
		Key:                     FlowKeyToProto(f.Key),
		StartTime:               f.StartTime,
		EndTime:                 f.EndTime,
		SourceLabels:            f.SourceLabels,
		DestLabels:              f.DestLabels,
		PacketsIn:               f.PacketsIn,
		PacketsOut:              f.PacketsOut,
		BytesIn:                 f.BytesIn,
		BytesOut:                f.BytesOut,
		NumConnectionsStarted:   f.NumConnectionsStarted,
		NumConnectionsCompleted: f.NumConnectionsCompleted,
		NumConnectionsLive:      f.NumConnectionsLive,
	}
}

func FlowKeyToProto(f *FlowKey) *proto.FlowKey {
	if f == nil {
		return nil
	}
	source := f.Source.Value()
	destination := f.Destination.Value()
	meta := f.Meta.Value()
	return &proto.FlowKey{
		SourceName:           source.SourceName,
		SourceNamespace:      source.SourceNamespace,
		SourceType:           source.SourceType,
		DestName:             destination.DestName,
		DestNamespace:        destination.DestNamespace,
		DestType:             destination.DestType,
		DestPort:             destination.DestPort,
		DestServiceName:      destination.DestServiceName,
		DestServiceNamespace: destination.DestServiceNamespace,
		DestServicePortName:  destination.DestServicePortName,
		DestServicePort:      destination.DestServicePort,
		Proto:                meta.Proto,
		Reporter:             meta.Reporter,
		Action:               meta.Action,
		Policies:             FlowLogPolicyToProto(f.Policies),
	}
}

func FlowLogPolicyToProto(h unique.Handle[PolicyTrace]) *proto.PolicyTrace {
	f := h.Value()
	var eps, pps []*proto.PolicyHit
	if f.EnforcedPolicies != "" {
		err := json.Unmarshal([]byte(f.EnforcedPolicies), &eps)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to unmarshal enforced policies")
		}
	}
	if f.PendingPolicies != "" {
		err := json.Unmarshal([]byte(f.PendingPolicies), &pps)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to unmarshal pending policies")
		}
	}
	return &proto.PolicyTrace{
		EnforcedPolicies: eps,
		PendingPolicies:  pps,
	}
}
