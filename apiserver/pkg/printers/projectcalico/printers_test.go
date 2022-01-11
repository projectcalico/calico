// Copyright (c) 2022 Tigera, Inc. All rights reserved.
//
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

package projectcalico

import (
	"reflect"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/kubernetes/pkg/printers"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

func TestPrintCalicoNodeStatus(t *testing.T) {
	var seconds uint32
	seconds = 10

	backThreeMinutes := time.Minute * time.Duration(-3)
	past := time.Now().Add(backThreeMinutes)

	status := calico.CalicoNodeStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "mystatus",
			CreationTimestamp: metav1.NewTime(past),
		},
		Spec: calico.CalicoNodeStatusSpec{
			Node: "node0",
			Classes: []calico.NodeStatusClassType{
				calico.NodeStatusClassTypeAgent,
				calico.NodeStatusClassTypeBGP,
				calico.NodeStatusClassTypeRoutes,
			},
			UpdatePeriodSeconds: &seconds,
		},
		Status: calico.CalicoNodeStatusStatus{
			LastUpdated: metav1.NewTime(past),
			Agent: calico.CalicoNodeAgentStatus{
				BIRDV4: calico.BGPDaemonStatus{
					State:                   calico.BGPDaemonStateReady,
					Version:                 "v0.3.3+birdv1.6.8",
					RouterID:                "172.17.0.0",
					LastBootTime:            "2021-09-19 20:48:56",
					LastReconfigurationTime: "2021-09-19 20:48:56",
				},
				BIRDV6: calico.BGPDaemonStatus{
					State:                   calico.BGPDaemonStateReady,
					Version:                 "v0.3.3+birdv1.6.8",
					RouterID:                "2001:20::8",
					LastBootTime:            "2021-09-19 20:48:56",
					LastReconfigurationTime: "2021-09-19 20:48:56",
				},
			},
			BGP: calico.CalicoNodeBGPStatus{
				NumberEstablishedV4:    2,
				NumberEstablishedV6:    1,
				NumberNotEstablishedV4: 1,
				NumberNotEstablishedV6: 0,
				PeersV4: []calico.CalicoNodePeer{
					{
						PeerIP: "172.17.8.104",
						Type:   calico.RouteSourceTypeNodeMesh,
						State:  calico.BGPSessionStateEstablished,
						Since:  "2016-11-21",
					},
					{
						PeerIP: "172.17.8.105",
						Type:   calico.RouteSourceTypeNodeMesh,
						State:  calico.BGPSessionStateEstablished,
						Since:  "2016-11-21",
					},
					{
						PeerIP: "172.17.8.106",
						Type:   calico.RouteSourceTypeNodeMesh,
						State:  calico.BGPSessionStateOpenSent,
						Since:  "2016-11-21",
					},
				},
				PeersV6: []calico.CalicoNodePeer{
					{
						PeerIP: "2001:20::8",
						Type:   calico.RouteSourceTypeNodeMesh,
						State:  calico.BGPSessionStateEstablished,
						Since:  "2016-11-21",
					},
				},
			},
			Routes: calico.CalicoNodeBGPRouteStatus{
				RoutesV4: []calico.CalicoNodeRoute{
					{
						Type:        calico.RouteTypeFIB,
						Destination: "172.17.0.0/16",
						Gateway:     "N/A",
						Interface:   "eth0",
						LearnedFrom: calico.CalicoNodeRouteLearnedFrom{
							SourceType: calico.RouteSourceTypeDirect,
						},
					},
					{
						Type:        calico.RouteTypeFIB,
						Destination: "192.168.10.0/24",
						Gateway:     "N/A",
						Interface:   "eth0",
						LearnedFrom: calico.CalicoNodeRouteLearnedFrom{
							SourceType: calico.RouteSourceTypeNodeMesh,
							PeerIP:     "172.17.0.5",
						},
					},
					{
						Type:        calico.RouteTypeFIB,
						Destination: "192.168.20.0/24",
						Gateway:     "N/A",
						Interface:   "eth0",
						LearnedFrom: calico.CalicoNodeRouteLearnedFrom{
							SourceType: calico.RouteSourceTypeNodeMesh,
							PeerIP:     "172.17.0.6",
						},
					},
				},
				RoutesV6: []calico.CalicoNodeRoute{
					{
						Type:        calico.RouteTypeFIB,
						Destination: "2001:20::8",
						Gateway:     "N/A",
						Interface:   "eth0",
						LearnedFrom: calico.CalicoNodeRouteLearnedFrom{
							SourceType: calico.RouteSourceTypeBGPPeer,
							PeerIP:     "2001:22::8",
						},
					},
				},
			},
		},
	}

	table := []struct {
		status   calico.CalicoNodeStatus
		option   printers.GenerateOptions
		expected []metav1.TableRow
	}{
		{
			status: status,
			option: printers.GenerateOptions{},
			expected: []metav1.TableRow{{Cells: []interface{}{"mystatus",
				"node0", "Agent,BGP,Routes", "10s", "3m", "3m ago"}}},
		},
		{
			status: status,
			option: printers.GenerateOptions{Wide: true},
			expected: []metav1.TableRow{{Cells: []interface{}{"mystatus",
				"node0", "Agent,BGP,Routes", "10s", "3m", "3m ago",
				"v4(Ready) v6(Ready)", "2/3", "1/1", "2", "1",
			}}},
		},
	}

	for i, test := range table {
		rows, err := printCalicoNodeStatus(&test.status, test.option)
		if err != nil {
			t.Fatalf("An error occurred generating table rows for Node: %#v", err)
		}
		for i := range rows {
			rows[i].Object.Object = nil
		}
		if !reflect.DeepEqual(test.expected, rows) {
			t.Errorf("%d mismatch: %s", i, diff.ObjectReflectDiff(test.expected, rows))
		}
	}
}
