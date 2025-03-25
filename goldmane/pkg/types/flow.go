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
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/proto"
	goproto "google.golang.org/protobuf/proto"
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
	Policies    unique.Handle[string]
}

func (k *FlowKey) Fields() logrus.Fields {
	return logrus.Fields{
		"source":      k.Source.Value(),
		"destination": k.Destination.Value(),
		"meta":        k.Meta.Value(),
		"policies":    k.Policies.Value(),
	}
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

func ProtoToFlowLogPolicy(p *proto.PolicyTrace) unique.Handle[string] {
	b, err := goproto.Marshal(p)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal policy trace")
		return unique.Make("")
	}
	return unique.Make(string(b))
}

// FlowIntoProto unpacks the memory optimized types.Flow object into the given proto.Flow object
// for use on the wire. Callers can re-use the same memory for the proto.Flow object across
// messages to reduce allocations.
func FlowIntoProto(f *Flow, pf *proto.Flow) {
	if pf == nil {
		logrus.Panic("FlowIntoProto called with nil proto")
	}

	// Reset the destination proto.
	goproto.Reset(pf)

	// Re-initialize any nil pointers after the reset call.
	if pf.Key == nil {
		pf.Key = &proto.FlowKey{}
	}
	if pf.Key.Policies == nil {
		pf.Key.Policies = &proto.PolicyTrace{}
	}

	// Copy key fields.
	flowKeyIntoProto(f.Key, pf.Key)

	// Copy flow fields.
	pf.StartTime = f.StartTime
	pf.EndTime = f.EndTime
	pf.SourceLabels = f.SourceLabels
	pf.DestLabels = f.DestLabels
	pf.PacketsIn = f.PacketsIn
	pf.PacketsOut = f.PacketsOut
	pf.BytesIn = f.BytesIn
	pf.BytesOut = f.BytesOut
	pf.NumConnectionsStarted = f.NumConnectionsStarted
	pf.NumConnectionsCompleted = f.NumConnectionsCompleted
	pf.NumConnectionsLive = f.NumConnectionsLive
}

func flowKeyIntoProto(k *FlowKey, pfk *proto.FlowKey) {
	if pfk == nil {
		logrus.Panic("flowKeyIntoProto called with nil proto")
	}

	source := k.Source.Value()
	destination := k.Destination.Value()
	meta := k.Meta.Value()
	pfk.SourceName = source.SourceName
	pfk.SourceNamespace = source.SourceNamespace
	pfk.SourceType = source.SourceType
	pfk.DestName = destination.DestName
	pfk.DestNamespace = destination.DestNamespace
	pfk.DestType = destination.DestType
	pfk.DestPort = destination.DestPort
	pfk.DestServiceName = destination.DestServiceName
	pfk.DestServiceNamespace = destination.DestServiceNamespace
	pfk.DestServicePortName = destination.DestServicePortName
	pfk.DestServicePort = destination.DestServicePort
	pfk.Proto = meta.Proto
	pfk.Reporter = meta.Reporter
	pfk.Action = meta.Action

	policies := k.Policies.Value()
	if err := goproto.Unmarshal([]byte(policies), pfk.Policies); err != nil {
		logrus.WithError(err).Error("Failed to unmarshal policy trace")
	}
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

func FlowLogPolicyToProto(h unique.Handle[string]) *proto.PolicyTrace {
	f := h.Value()
	var p proto.PolicyTrace
	if f != "" {
		if err := goproto.Unmarshal([]byte(f), &p); err != nil {
			logrus.WithError(err).Error("Failed to unmarshal policy trace")
		}
	}
	return &p
}
