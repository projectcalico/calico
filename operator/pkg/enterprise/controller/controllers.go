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

package controller

import (
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/applicationlayer"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/authentication"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/egressgateway"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/intrusiondetection"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/istio/waypoint"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/logcollector"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/logstorage"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/manager"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/monitor"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/nonclusterhost"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/otelcollector"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/packetcapture"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/policyrecommendation"
)

// Controllers returns the reconcilers only Calico Enterprise runs, for the caller to
// pass to the controller manager. Registering here is what gates them, so the
// controllers themselves do not check the variant. They live in their own package
// rather than in pkg/enterprise, which their own tests import.
func Controllers(variant operatorv1.ProductVariant) []options.Controller {
	if !variant.IsEnterprise() {
		return nil
	}
	return []options.Controller{
		{Name: "Monitor", Add: monitor.Add},
		{Name: "ApplicationLayer", Add: applicationlayer.Add},
		{Name: "EgressGateway", Add: egressgateway.Add},
		{Name: "PacketCapture", Add: packetcapture.Add},
		{Name: "OpenTelemetryCollector", Add: otelcollector.Add},
		{Name: "IntrusionDetection", Add: intrusiondetection.Add},
		{Name: "LogCollector", Add: logcollector.Add},
		{Name: "LogStorage", Add: logstorage.Add},
		{Name: "IstioWaypoint", Add: waypoint.Add},
		{Name: "Manager", Add: manager.Add},
		{Name: "NonClusterHost", Add: nonclusterhost.Add},
		{Name: "Authentication", Add: authentication.Add},
		{Name: "PolicyRecommendation", Add: policyrecommendation.Add},
	}
}
