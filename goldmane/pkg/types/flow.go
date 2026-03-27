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
	"slices"
	"strings"
	"sync"
	"unique"

	"github.com/sirupsen/logrus"
	goproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/proto"
)

// FlowConfig contains configuration options for flow aggregation
type FlowConfig struct {
	// MaxSourceIPs is the maximum number of source IPs to store per flow
	// A value of 0 means no limit
	MaxSourceIPs int

	// MaxSourcePorts is the maximum number of source ports to store per flow
	// A value of 0 means no limit
	MaxSourcePorts int
}

// DefaultFlowConfig returns the default configuration for flows
func DefaultFlowConfig() *FlowConfig {
	return &FlowConfig{
		MaxSourceIPs:   100, // Default limit of 100 IPs per flow
		MaxSourcePorts: 100, // Default limit of 100 ports per flow
	}
}

var (
	// Object pools to reduce GC pressure during high-throughput merging
	stringMapPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]bool, 128)
		},
	}
	int64MapPool = sync.Pool{
		New: func() interface{} {
			return make(map[int64]bool, 128)
		},
	}
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
	DestIP               string
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

func NewFlowKey(source *FlowKeySource, dst *FlowKeyDestination, meta *FlowKeyMeta, policies *proto.PolicyTrace) *FlowKey {
	return &FlowKey{
		source:   unique.Make(*source),
		dest:     unique.Make(*dst),
		meta:     unique.Make(*meta),
		policies: ProtoToFlowLogPolicy(policies),
	}
}

// FlowKey is a unique key for a flow. It matches the protobuf API exactly. Unfortunately,
// we cannot use the protobuf API structures as map keys due to private fields that are inserted
// by the protobuf Go code generation. So we need a copy of the struct here.
//
// This struct should encapsulate the full set of fields avaialble on proto.FlowKey structure, but without the private fields.
type FlowKey struct {
	source   unique.Handle[FlowKeySource]
	dest     unique.Handle[FlowKeyDestination]
	meta     unique.Handle[FlowKeyMeta]
	policies unique.Handle[string]
}

func (k *FlowKey) Fields() logrus.Fields {
	return logrus.Fields{
		"source":      k.source.Value(),
		"destination": k.dest.Value(),
		"meta":        k.meta.Value(),
		"policies":    k.policies.Value(),
	}
}

func (k *FlowKey) Policies() unique.Handle[string] {
	return k.policies
}

func (k *FlowKey) Action() proto.Action {
	return k.meta.Value().Action
}

func (k *FlowKey) Reporter() proto.Reporter {
	return k.meta.Value().Reporter
}

func (k *FlowKey) Proto() string {
	return k.meta.Value().Proto
}

func (k *FlowKey) SourceType() proto.EndpointType {
	return k.source.Value().SourceType
}

func (k *FlowKey) SourceName() string {
	return k.source.Value().SourceName
}

func (k *FlowKey) SourceNamespace() string {
	return k.source.Value().SourceNamespace
}

func (k *FlowKey) DestType() proto.EndpointType {
	return k.dest.Value().DestType
}

func (k *FlowKey) DestName() string {
	return k.dest.Value().DestName
}

func (k *FlowKey) DestNamespace() string {
	return k.dest.Value().DestNamespace
}

func (k *FlowKey) DestPort() int64 {
	return k.dest.Value().DestPort
}

func (k *FlowKey) DestServiceName() string {
	return k.dest.Value().DestServiceName
}

func (k *FlowKey) DestServiceNamespace() string {
	return k.dest.Value().DestServiceNamespace
}

func (k *FlowKey) DestServicePortName() string {
	return k.dest.Value().DestServicePortName
}

func (k *FlowKey) DestServicePort() int64 {
	return k.dest.Value().DestServicePort
}

func (k *FlowKey) DestIP() string {
	return k.dest.Value().DestIP
}

// This struct should be an exact copy of the proto.Flow structure, but without the private fields.
type Flow struct {
	Key                     *FlowKey
	StartTime               int64
	EndTime                 int64
	SourceLabels            unique.Handle[string]
	DestLabels              unique.Handle[string]
	SourceIPs               []string
	SourcePorts             []int64
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
		SourceLabels:            toHandles(p.SourceLabels),
		DestLabels:              toHandles(p.DestLabels),
		SourceIPs:               p.SourceIps,
		SourcePorts:             p.SourcePorts,
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
	return NewFlowKey(
		&FlowKeySource{
			SourceName:      p.SourceName,
			SourceNamespace: p.SourceNamespace,
			SourceType:      p.SourceType,
		},
		&FlowKeyDestination{
			DestName:             p.DestName,
			DestNamespace:        p.DestNamespace,
			DestType:             p.DestType,
			DestIP:               p.DestIp,
			DestPort:             p.DestPort,
			DestServiceName:      p.DestServiceName,
			DestServiceNamespace: p.DestServiceNamespace,
			DestServicePortName:  p.DestServicePortName,
			DestServicePort:      p.DestServicePort,
		},
		&FlowKeyMeta{
			Proto:    p.Proto,
			Reporter: p.Reporter,
			Action:   p.Action,
		},
		p.Policies,
	)
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
	pf.SourceLabels = fromHandles(f.SourceLabels)
	pf.DestLabels = fromHandles(f.DestLabels)
	pf.SourceIps = f.SourceIPs
	pf.SourcePorts = f.SourcePorts
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

	source := k.source.Value()
	destination := k.dest.Value()
	meta := k.meta.Value()
	pfk.SourceName = source.SourceName
	pfk.SourceNamespace = source.SourceNamespace
	pfk.SourceType = source.SourceType
	pfk.DestName = destination.DestName
	pfk.DestNamespace = destination.DestNamespace
	pfk.DestType = destination.DestType
	pfk.DestIp = destination.DestIP
	pfk.DestPort = destination.DestPort
	pfk.DestServiceName = destination.DestServiceName
	pfk.DestServiceNamespace = destination.DestServiceNamespace
	pfk.DestServicePortName = destination.DestServicePortName
	pfk.DestServicePort = destination.DestServicePort
	pfk.Proto = meta.Proto
	pfk.Reporter = meta.Reporter
	pfk.Action = meta.Action

	policies := k.Policies().Value()
	if err := goproto.Unmarshal([]byte(policies), pfk.Policies); err != nil {
		logrus.WithError(err).Error("Failed to unmarshal policy trace")
	}
}

func FlowToProto(f *Flow) *proto.Flow {
	return &proto.Flow{
		Key:                     flowKeyToProto(f.Key),
		StartTime:               f.StartTime,
		EndTime:                 f.EndTime,
		SourceLabels:            fromHandles(f.SourceLabels),
		DestLabels:              fromHandles(f.DestLabels),
		SourceIps:               f.SourceIPs,
		SourcePorts:             f.SourcePorts,
		PacketsIn:               f.PacketsIn,
		PacketsOut:              f.PacketsOut,
		BytesIn:                 f.BytesIn,
		BytesOut:                f.BytesOut,
		NumConnectionsStarted:   f.NumConnectionsStarted,
		NumConnectionsCompleted: f.NumConnectionsCompleted,
		NumConnectionsLive:      f.NumConnectionsLive,
	}
}

func flowKeyToProto(f *FlowKey) *proto.FlowKey {
	if f == nil {
		return nil
	}
	source := f.source.Value()
	destination := f.dest.Value()
	meta := f.meta.Value()
	return &proto.FlowKey{
		SourceName:           source.SourceName,
		SourceNamespace:      source.SourceNamespace,
		SourceType:           source.SourceType,
		DestName:             destination.DestName,
		DestNamespace:        destination.DestNamespace,
		DestType:             destination.DestType,
		DestIp:               destination.DestIP,
		DestPort:             destination.DestPort,
		DestServiceName:      destination.DestServiceName,
		DestServiceNamespace: destination.DestServiceNamespace,
		DestServicePortName:  destination.DestServicePortName,
		DestServicePort:      destination.DestServicePort,
		Proto:                meta.Proto,
		Reporter:             meta.Reporter,
		Action:               meta.Action,
		Policies:             FlowLogPolicyToProto(f.Policies()),
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

func toHandles(labels []string) unique.Handle[string] {
	slices.Sort(labels)
	return unique.Make(strings.Join(labels, ","))
}

func fromHandles(handles unique.Handle[string]) []string {
	if handles.Value() == "" {
		return nil
	}
	return strings.Split(handles.Value(), ",")
}

// MergeFlows combines two flows with the same FlowKey, merging their source IP and port arrays
// while respecting the provided limits. When merging, duplicate IPs/ports are removed and
// arrays are truncated to the specified limits if needed.
// This implementation is optimized for high-scale performance.
func MergeFlows(f1, f2 *Flow, maxIPs, maxPorts int) *Flow {
	if f1 == nil {
		return f2
	}
	if f2 == nil {
		return f1
	}

	// Fast path: if either flow already exceeds limits, just take the first one
	// This avoids expensive merging when we're already at capacity
	if maxIPs > 0 && len(f1.SourceIPs) >= maxIPs {
		maxIPs = len(f1.SourceIPs) // Don't expand beyond current size
	}
	if maxPorts > 0 && len(f1.SourcePorts) >= maxPorts {
		maxPorts = len(f1.SourcePorts) // Don't expand beyond current size
	}

	sourceIPs := mergeUniqueStrings(f1.SourceIPs, f2.SourceIPs, maxIPs)
	sourcePorts := mergeUniqueInt64s(f1.SourcePorts, f2.SourcePorts, maxPorts)

	// Create merged flow with aggregated statistics
	return &Flow{
		Key:                     f1.Key, // Same key for both flows
		StartTime:               min(f1.StartTime, f2.StartTime),
		EndTime:                 max(f1.EndTime, f2.EndTime),
		SourceLabels:            f1.SourceLabels, // Assuming same labels for same key
		DestLabels:              f1.DestLabels,   // Assuming same labels for same key
		SourceIPs:               sourceIPs,
		SourcePorts:             sourcePorts,
		PacketsIn:               f1.PacketsIn + f2.PacketsIn,
		PacketsOut:              f1.PacketsOut + f2.PacketsOut,
		BytesIn:                 f1.BytesIn + f2.BytesIn,
		BytesOut:                f1.BytesOut + f2.BytesOut,
		NumConnectionsStarted:   f1.NumConnectionsStarted + f2.NumConnectionsStarted,
		NumConnectionsCompleted: f1.NumConnectionsCompleted + f2.NumConnectionsCompleted,
		NumConnectionsLive:      f1.NumConnectionsLive + f2.NumConnectionsLive,
	}
}

// mergeUniqueStrings efficiently merges two string slices, removing duplicates.
// Optimized for high performance at scale using object pooling.
func mergeUniqueStrings(s1, s2 []string, maxSize int) []string {
	if maxSize == 0 {
		maxSize = len(s1) + len(s2) // No limit
	}

	// Pre-allocate result slice with known capacity to avoid reallocations
	result := make([]string, 0, min(maxSize, len(s1)+len(s2)))

	// Get a map from the pool and reset it
	seen := stringMapPool.Get().(map[string]bool)
	defer func() {
		// Clear the map and return to pool
		for k := range seen {
			delete(seen, k)
		}
		stringMapPool.Put(seen)
	}()

	// Add from first slice
	for _, s := range s1 {
		if len(result) >= maxSize {
			break // Early termination when limit reached
		}
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	// Add from second slice
	for _, s := range s2 {
		if len(result) >= maxSize {
			break // Early termination when limit reached
		}
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	// Only sort if we have a reasonable number of elements
	// For very large arrays, the cost of sorting may outweigh benefits
	if len(result) <= 1000 {
		slices.Sort(result)
	}

	return result
}

// mergeUniqueInt64s efficiently merges two int64 slices, removing duplicates.
// Optimized for high performance at scale using object pooling.
func mergeUniqueInt64s(s1, s2 []int64, maxSize int) []int64 {
	if maxSize == 0 {
		maxSize = len(s1) + len(s2) // No limit
	}

	// Pre-allocate result slice with known capacity to avoid reallocations
	result := make([]int64, 0, min(maxSize, len(s1)+len(s2)))

	// Get a map from the pool and reset it
	seen := int64MapPool.Get().(map[int64]bool)
	defer func() {
		// Clear the map and return to pool
		for k := range seen {
			delete(seen, k)
		}
		int64MapPool.Put(seen)
	}()

	// Add from first slice
	for _, p := range s1 {
		if len(result) >= maxSize {
			break // Early termination when limit reached
		}
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}

	// Add from second slice
	for _, p := range s2 {
		if len(result) >= maxSize {
			break // Early termination when limit reached
		}
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}

	// Only sort if we have a reasonable number of elements
	// For very large arrays, the cost of sorting may outweigh benefits
	if len(result) <= 1000 {
		slices.Sort(result)
	}

	return result
}

// MergeFlowsWithConfig is a convenience function that merges flows using the provided configuration
func MergeFlowsWithConfig(f1, f2 *Flow, config *FlowConfig) *Flow {
	if config == nil {
		config = DefaultFlowConfig()
	}
	return MergeFlows(f1, f2, config.MaxSourceIPs, config.MaxSourcePorts)
}
