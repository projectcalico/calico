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
	"path"
	"syscall"
	"time"

	"github.com/projectcalico/calico/felix/collector/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/sirupsen/logrus"
)

func StartServerAndWatch(num int) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := ensureGoldmaneSocketDirectory(goldmane.LocalGoldmaneServer)
	if err != nil {
		logrus.WithError(err).Error("Failed to create goldmane unix server")
		return
	}
	nodeServer := goldmane.NewNodeServer(goldmane.LocalGoldmaneServer)
	err = nodeServer.Run()
	if err != nil {
		logrus.WithError(err).Error("Failed to start node local goldmane server")
		return
	}

	infinitLoop := num < 0
	var count int
	for {
		if ctx.Err() != nil ||
			(!infinitLoop && count >= num) {
			logrus.Debug("Closing goldmane unix server")
			nodeServer.Stop()
			cleanupGoldmaneSocket()
			return
		}

		flows := nodeServer.ListAndFlush()
		for _, flow := range flows {
			fmt.Printf("%s", flowToString(flow))
		}
		count = count + len(flows)
		time.Sleep(time.Second)
	}
}

func flowToString(f *types.Flow) string {
	startTime := time.Unix(f.StartTime, 0)
	policyTrace := types.FlowLogPolicyToProto(f.Key.Policies())
	return fmt.Sprintf(
		"- Time=%v Reporter=%v Action=%v\n"+
			"  Src=%s(%s/%s) Dst=%s(%s/%s) Svc=%s/%s Proto=%s(%v svc:%s/%v)\n"+
			"  Counts={Ingress: %vPkts/%vBytes Egress:%vPkts/%vBytes} Connections={Started:%v Completed:%v Live:%v}\n"+
			"  Enforced:\n%v\n"+
			"  Pending:\n%v\n",
		startTime, f.Key.Reporter(), f.Key.Action(),
		endpointTypeToString(f.Key.SourceType()), f.Key.SourceNamespace(), f.Key.SourceName(),
		endpointTypeToString(f.Key.DestType()), f.Key.DestNamespace(), f.Key.DestName(),
		f.Key.DestServiceName(), f.Key.DestServiceNamespace(),
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
		panic(fmt.Sprintf("Unexpected endpoint type: %v", ep))
	}
}

func policyHitsToString(policies []*proto.PolicyHit) string {
	var out string
	for _, p := range policies {
		out = out + fmt.Sprintf("  - %v", p)
	}
	return out
}

func ensureGoldmaneSocketDirectory(addr string) error {
	path := path.Dir(addr)
	// Check if goldmane unix server exists at the expected location.
	logrus.Debug("Checking if goldmane unix server exists.")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logrus.WithField("path", path).Debug("Goldmane unix socket directory does not exist.")
		err := os.MkdirAll(path, 0o600)
		if err != nil {
			return err
		}
		logrus.WithField("path", path).Debug("Created goldmane unix server directory.")
	}
	return nil
}

func cleanupGoldmaneSocket() {
	if goldmane.NodeSocketExists() {
		err := os.Remove(goldmane.LocalGoldmaneServer)
		if err != nil {
			logrus.WithError(err).Errorf("Failed to remove goldmane node socket")
		}
	}
}
