// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"fmt"
	"reflect"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/printers"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

func CalicoNodeStatusAddHandlers(h printers.PrintHandler) {
	calicoNodeStatusColumnDefinitions := []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Format: "name", Description: metav1.ObjectMeta{}.SwaggerDoc()["name"]},
		{Name: "Node", Type: "string", Priority: 0, Description: "The node name identifies the Calico node instance for node status."},
		{Name: "Classes", Type: "string", Description: "Types of information to monitor for this calico/node."},
		{Name: "Update Interval", Type: "string", Description: "Period in seconds at which CalicoNodeStatus should be updated."},
		{Name: "Age", Type: "string", Description: metav1.ObjectMeta{}.SwaggerDoc()["creationTimestamp"]},
		{Name: "last Updated", Type: "string", Description: "Last time the status has been updated"},
		{Name: "Agent State", Type: "string", Priority: 1, Description: "The state of the BGP Daemon."},
		{Name: "ESTABLISHED-V4", Type: "string", Priority: 1, Description: "Number of V4 BGP Peers in the format of established/total."},
		{Name: "ESTABLISHED-V6", Type: "string", Priority: 1, Description: "Number of V6 BGP Peers in the format of established/total."},
		{Name: "NUM-V4-ROUTES", Type: "string", Priority: 1, Description: "Number of V4 routes learned from BGP peers."},
		{Name: "NUM-V6-ROUTES", Type: "string", Priority: 1, Description: "Number of V6 routes learned from BGP peers."},
	}
	h.TableHandler(calicoNodeStatusColumnDefinitions, printCalicoNodeStatusList)
	h.TableHandler(calicoNodeStatusColumnDefinitions, printCalicoNodeStatus)
}

func printCalicoNodeStatusList(statusList *calico.CalicoNodeStatusList, options printers.GenerateOptions) ([]metav1.TableRow, error) {
	rows := make([]metav1.TableRow, 0, len(statusList.Items))
	for i := range statusList.Items {
		r, err := printCalicoNodeStatus(&statusList.Items[i], options)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	return rows, nil
}

func printCalicoNodeStatus(status *calico.CalicoNodeStatus, options printers.GenerateOptions) ([]metav1.TableRow, error) {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: status},
	}

	// Define a function return true if the status contains information about a class.
	hasClass := func(c calico.NodeStatusClassType) bool {
		for _, class := range status.Spec.Classes {
			if class == c {
				return true
			}
		}
		return false
	}

	var classes string
	for _, class := range status.Spec.Classes {
		classes += fmt.Sprintf("%s,", class)
	}
	classesStr := fmt.Sprintf("%s", strings.TrimSuffix(classes, ","))

	var lastUpdatedStr string
	lastUpdatedDate := status.Status.LastUpdated
	if !lastUpdatedDate.IsZero() {
		lastUpdatedStr = fmt.Sprintf("%s ago", translateTimestampSince(lastUpdatedDate))
	}

	row.Cells = append(row.Cells,
		status.Name,
		status.Spec.Node,
		classesStr,
		fmt.Sprintf("%ds", *status.Spec.UpdatePeriodSeconds),
		translateTimestampSince(status.CreationTimestamp),
		lastUpdatedStr)

	if options.Wide {
		var agentStateStr string
		if hasClass(calico.NodeStatusClassTypeAgent) {
			agent := status.Status.Agent
			if !reflect.ValueOf(agent.BIRDV4).IsZero() {
				agentStateStr = fmt.Sprintf("v4(%s) ", agent.BIRDV4.State)
			}
			if !reflect.ValueOf(agent.BIRDV6).IsZero() {
				agentStateStr += fmt.Sprintf("v6(%s)", agent.BIRDV6.State)
			}
		}

		var V4PeersStr, V6PeersStr string
		if hasClass(calico.NodeStatusClassTypeBGP) {
			bgp := status.Status.BGP
			if !reflect.ValueOf(bgp.PeersV4).IsZero() {
				V4PeersStr = fmt.Sprintf("%d/%d", bgp.NumberEstablishedV4, len(bgp.PeersV4))
			}
			if !reflect.ValueOf(bgp.PeersV6).IsZero() {
				V6PeersStr = fmt.Sprintf("%d/%d", bgp.NumberEstablishedV6, len(bgp.PeersV6))
			}
		}

		getNumberOfBGPRoutes := func(routes []calico.CalicoNodeRoute) int {
			n := 0
			for _, r := range routes {
				if (r.LearnedFrom.SourceType == calico.RouteSourceTypeBGPPeer) ||
					(r.LearnedFrom.SourceType == calico.RouteSourceTypeNodeMesh) {
					n++
				}
			}
			return n
		}

		var V4RoutesStr, V6RoutesStr string
		if hasClass(calico.NodeStatusClassTypeRoutes) {
			routes := status.Status.Routes
			if !reflect.ValueOf(routes.RoutesV4).IsZero() {
				V4RoutesStr = fmt.Sprintf("%d", getNumberOfBGPRoutes(routes.RoutesV4))
			}
			if !reflect.ValueOf(routes.RoutesV6).IsZero() {
				V6RoutesStr = fmt.Sprintf("%d", getNumberOfBGPRoutes(routes.RoutesV6))
			}
		}

		row.Cells = append(row.Cells, agentStateStr, V4PeersStr, V6PeersStr, V4RoutesStr, V6RoutesStr)
	}

	return []metav1.TableRow{row}, nil
}
