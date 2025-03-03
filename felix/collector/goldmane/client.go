// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package goldmane

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/proto"
)

type GoldmaneReporter struct {
	address string
	client  *client.FlowClient
	once    sync.Once
}

func NewReporter(addr string) *GoldmaneReporter {
	return &GoldmaneReporter{
		address: addr,
		client:  client.NewFlowClient(addr),
	}
}

func (g *GoldmaneReporter) Start() error {
	var err error
	g.once.Do(func() {
		var grpcClient *grpc.ClientConn
		grpcClient, err = grpc.NewClient(g.address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return
		}
		go g.client.Run(context.Background(), grpcClient)
	})
	return err
}

func (g *GoldmaneReporter) Report(logSlice any) error {
	switch logs := logSlice.(type) {
	case []*flowlog.FlowLog:
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithField("num", len(logs)).Debug("Dispatching flow logs to goldmane")
		}
		for _, l := range logs {
			g.client.Push(convertFlowlogToGoldmane(l))
		}
	default:
		logrus.Panic("Unexpected kind of log dispatcher")
	}
	return nil
}

func convertType(t endpoint.Type) proto.EndpointType {
	var pt proto.EndpointType
	switch t {
	case endpoint.Wep:
		pt = proto.EndpointType_WorkloadEndpoint
	case endpoint.Hep:
		pt = proto.EndpointType_HostEndpoint
	case endpoint.Ns:
		pt = proto.EndpointType_NetworkSet
	case endpoint.Net:
		pt = proto.EndpointType_PrivateNetwork
	default:
		logrus.WithField("type", t).Warn("Unexpected endpoint type")
	}
	return pt
}

func convertReporter(r flowlog.ReporterType) proto.Reporter {
	switch r {
	case flowlog.ReporterSrc:
		return proto.Reporter_Src
	case flowlog.ReporterDst:
		return proto.Reporter_Dst
	}
	logrus.WithField("reporter", r).Fatal("BUG: Unexpected reporter")
	return proto.Reporter_Dst
}

func convertAction(a flowlog.Action) proto.Action {
	switch a {
	case flowlog.ActionAllow:
		return proto.Action_Allow
	case flowlog.ActionDeny:
		return proto.Action_Deny
	default:
		logrus.WithField("action", a).Fatal("BUG: Unexpected action")
	}
	return proto.Action_ActionUnspecified
}

func convertFlowlogToGoldmane(fl *flowlog.FlowLog) *proto.Flow {
	return &proto.Flow{
		StartTime: fl.StartTime.Unix(),
		EndTime:   fl.StartTime.Unix(),

		PacketsIn:               int64(fl.PacketsIn),
		PacketsOut:              int64(fl.PacketsOut),
		BytesIn:                 int64(fl.BytesIn),
		BytesOut:                int64(fl.BytesOut),
		NumConnectionsLive:      int64(fl.NumFlows),
		NumConnectionsStarted:   int64(fl.NumFlowsStarted),
		NumConnectionsCompleted: int64(fl.NumFlowsCompleted),

		SourceLabels: ensureLabels(fl.SrcLabels),
		DestLabels:   ensureLabels(fl.DstLabels),

		Key: &proto.FlowKey{
			SourceName:      fl.SrcMeta.AggregatedName,
			SourceNamespace: fl.SrcMeta.Namespace,
			SourceType:      convertType(fl.SrcMeta.Type),

			DestName:      fl.DstMeta.AggregatedName,
			DestNamespace: fl.DstMeta.Namespace,
			DestType:      convertType(fl.DstMeta.Type),
			DestPort:      int64(fl.Tuple.L4Dst),

			DestServiceName:      fl.DstService.Name,
			DestServiceNamespace: fl.DstService.Namespace,
			DestServicePortName:  fl.DstService.PortName,
			DestServicePort:      int64(fl.DstService.PortNum),

			Proto:    utils.ProtoToString(fl.Tuple.Proto),
			Reporter: convertReporter(fl.Reporter),
			Action:   convertAction(fl.Action),
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: toPolicyHits(fl.FlowEnforcedPolicySet),
				PendingPolicies:  toPolicyHits(fl.FlowPendingPolicySet),
			},
		},
	}
}

func ConvertGoldmaneToFlowlog(gl *proto.Flow) flowlog.FlowLog {
	fl := flowlog.FlowLog{
		StartTime: time.Unix(gl.StartTime, 0),
		EndTime:   time.Unix(gl.EndTime, 0),
	}
	fl.PacketsIn = int(gl.PacketsIn)
	fl.PacketsOut = int(gl.PacketsOut)
	fl.BytesIn = int(gl.BytesIn)
	fl.BytesOut = int(gl.BytesOut)
	fl.NumFlows = int(gl.NumConnectionsLive)
	fl.NumFlowsStarted = int(gl.NumConnectionsStarted)
	fl.NumFlowsCompleted = int(gl.NumConnectionsCompleted)

	fl.SrcLabels = ensureFlowLogLabels(gl.SourceLabels)
	fl.DstLabels = ensureFlowLogLabels(gl.DestLabels)
	fl.FlowEnforcedPolicySet = toFlowPolicySet(gl.Key.Policies.EnforcedPolicies)
	fl.FlowPendingPolicySet = toFlowPolicySet(gl.Key.Policies.PendingPolicies)

	fl.SrcMeta = endpoint.Metadata{
		Type:           endpoint.Type(gl.Key.SourceType),
		Namespace:      gl.Key.SourceNamespace,
		Name:           flowlog.FieldNotIncluded,
		AggregatedName: gl.Key.SourceName,
	}
	fl.DstMeta = endpoint.Metadata{
		Type:           endpoint.Type(gl.Key.DestType),
		Namespace:      gl.Key.DestNamespace,
		Name:           flowlog.FieldNotIncluded,
		AggregatedName: gl.Key.DestName,
	}
	fl.DstService = flowlog.FlowService{
		Namespace: gl.Key.DestServiceNamespace,
		Name:      gl.Key.DestServiceName,
		PortName:  gl.Key.DestServicePortName,
		PortNum:   int(gl.Key.DestServicePort),
	}
	fl.Tuple = tuple.Tuple{
		Proto: utils.StringToProto(gl.Key.Proto),
		L4Dst: int(gl.Key.DestPort),
	}
	fl.Reporter = flowlog.ReporterType(gl.Key.Reporter)
	fl.Action = flowlog.Action(gl.Key.Action)
	return fl
}

// toPolicyHits converts a FlowPolicySet to a slice of policy hits in Goldmane protobuf format.
func toPolicyHits(labels flowlog.FlowPolicySet) []*proto.PolicyHit {
	var hits []*proto.PolicyHit
	for p := range labels {
		h, err := proto.HitFromString(p)
		if err != nil {
			logrus.WithError(err).WithField("label", p).Panic("Failed to parse policy hit")
		}
		hits = append(hits, h)
	}
	return hits
}

// toFlowPolicySet converts a slice of policy hits in Goldmane protobuf format to a FlowPolicySet.
func toFlowPolicySet(policies []*proto.PolicyHit) flowlog.FlowPolicySet {
	if policies == nil {
		return nil
	}

	policySet := make(flowlog.FlowPolicySet)
	for _, pol := range policies {
		policySet[pol.ToString()] = struct{}{}
	}
	return policySet
}

func ensureLabels(labels map[string]string) []string {
	if labels == nil {
		return nil
	}
	return utils.FlattenLabels(labels)
}

func ensureFlowLogLabels(lables []string) map[string]string {
	if lables == nil {
		return map[string]string{}
	}
	return utils.UnflattenLabels(lables)
}
