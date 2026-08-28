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
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/enterprise/apiserver"
	"github.com/projectcalico/calico/operator/pkg/enterprise/clusterconnection"
	"github.com/projectcalico/calico/operator/pkg/enterprise/csr"
	"github.com/projectcalico/calico/operator/pkg/enterprise/gatewayapi"
	"github.com/projectcalico/calico/operator/pkg/enterprise/goldmane"
	"github.com/projectcalico/calico/operator/pkg/enterprise/installation"
	"github.com/projectcalico/calico/operator/pkg/enterprise/istio"
	eoptions "github.com/projectcalico/calico/operator/pkg/enterprise/options"
	"github.com/projectcalico/calico/operator/pkg/enterprise/tiers"
	"github.com/projectcalico/calico/operator/pkg/enterprise/whisker"
	"github.com/projectcalico/calico/operator/pkg/enterprise/windows"
	"github.com/projectcalico/calico/operator/pkg/extensions"
)

// New builds the Calico Enterprise extensions. After the monorepo split this is what
// calico-private's main constructs instead.
func New(variant operatorv1.ProductVariant, o eoptions.Options) extensions.Extensions {
	// Enterprise has two spellings, so match on the product rather than the constant:
	// an Installation asking for the deprecated TigeraSecureEnterprise still gets the
	// Enterprise extensions.
	if variant.IsEnterprise() {
		return extensions.New(extensions.Set{
			Installation:      installation.New(variant, o),
			Windows:           windows.New(variant),
			APIServer:         apiserver.New(variant, o),
			ClusterConnection: clusterconnection.New(variant),
			Tiers:             tiers.New(o),
			CSR:               csr.New(),
			Istio:             istio.New(variant),
			Goldmane:          goldmane.New(variant),
			Whisker:           whisker.New(variant),
			GatewayAPI:        gatewayapi.New(variant),
		})
	}

	if variant == operatorv1.Calico {
		// Clean up what a prior Enterprise installation left behind.
		return extensions.New(extensions.Set{APIServer: apiserver.CalicoCleanup{}})
	}

	return extensions.Extensions{}
}
