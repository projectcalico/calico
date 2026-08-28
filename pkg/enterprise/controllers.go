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

package enterprise

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/enterprise/controller/applicationlayer"
	"github.com/tigera/operator/pkg/enterprise/controller/egressgateway"
	"github.com/tigera/operator/pkg/enterprise/controller/monitor"
	"github.com/tigera/operator/pkg/enterprise/controller/otelcollector"
	"github.com/tigera/operator/pkg/enterprise/controller/packetcapture"
)

// Controllers returns the reconcilers only Calico Enterprise runs, for the caller to
// pass to the controller manager. Registering here is what gates them, so the
// controllers themselves do not check the variant.
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
	}
}
