// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowlogs

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/local"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

func RunFlowsCmd(num int) {
	// Command-line tools should log to stderr to avoid confusion with the output.
	logrus.SetOutput(os.Stderr)
	StartAndWatch(num)
	os.Exit(0)
}

func StartAndWatch(num int) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	flowServer := local.NewFlowServer(local.SocketDir)
	err := flowServer.Run()
	if err != nil {
		logrus.WithError(err).Error("Failed to start local flow server")
		return
	}
	defer flowServer.Stop()

	flowServer.Watch(ctx, num, time.Second, func(flow *types.Flow) {
		fmt.Printf("%s", flowToString(flow))
	})
}

func flowToString(f *types.Flow) string {
	startTime := time.Unix(f.StartTime, 0)
	policyTrace := types.FlowLogPolicyToProto(f.Key.Policies())
	return fmt.Sprintf(
		"- Time=%v Reporter=%v Action=%v\n"+
			"  Src={%s(%s/%s)} Dst={%s(%s/%s) Svc:%s/%s} Proto={%s(%v) Svc:%s/%v}\n"+
			"  Counts={Ingress: %vPkts/%vBytes Egress:%vPkts/%vBytes} Connections={Started:%v Completed:%v Live:%v}\n"+
			"  Enforced:\n%v\n"+
			"  Pending:\n%v\n",
		startTime.Local(), f.Key.Reporter(), f.Key.Action(),
		endpointTypeToString(f.Key.SourceType()), f.Key.SourceNamespace(), f.Key.SourceName(),
		endpointTypeToString(f.Key.DestType()), f.Key.DestNamespace(), f.Key.DestName(),
		f.Key.DestServiceNamespace(), f.Key.DestServiceName(),
		f.Key.Proto(), f.Key.DestPort(), f.Key.DestServicePortName(), f.Key.DestServicePort(),
		f.PacketsIn, f.BytesIn, f.PacketsOut, f.BytesOut,
		f.NumConnectionsStarted, f.NumConnectionsCompleted, f.NumConnectionsLive,
		policyHitsToString(policyTrace.EnforcedPolicies), policyHitsToString(policyTrace.PendingPolicies),
	)
}

func endpointTypeToString(ep proto.EndpointType) string {
	switch ep {
	case proto.EndpointType_WorkloadEndpoint:
		return "wep"
	case proto.EndpointType_HostEndpoint:
		return "hep"
	case proto.EndpointType_NetworkSet:
		return "ns"
	case proto.EndpointType_Network:
		return "net"
	default:
		return "unknown"
	}
}

func policyHitsToString(policies []*proto.PolicyHit) string {
	var out string
	for _, p := range policies {
		out = out + fmt.Sprintf("  - %v", p)
	}
	return out
}
