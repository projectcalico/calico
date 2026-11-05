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

package istio

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	gatewayAPIWarningKey = "istio-gateway-api-crds"

	gatewayAPIBundleVersionAnnotation = "gateway.networking.k8s.io/bundle-version"
)

// istioGatewayAPIMinimumVersions mirrors MinimumCRDVersions in the bundled
// Istio's pkg/config/schema/gatewayapi/minimumversions.go. istiod does not watch
// a CRD below its minimum, so routes of that kind stop working with nothing but
// an istiod log line to show for it. The operator never updates a Gateway API
// CRD that already exists, so an upgraded cluster can keep CRDs that are too
// old.
var istioGatewayAPIMinimumVersions = map[string]*semver.Version{
	"grpcroutes.gateway.networking.k8s.io":         semver.MustParse("1.1.0"),
	"backendtlspolicies.gateway.networking.k8s.io": semver.MustParse("1.4.0"),
	"tlsroutes.gateway.networking.k8s.io":          semver.MustParse("1.5.0"),
	"tcproutes.gateway.networking.k8s.io":          semver.MustParse("1.6.0"),
}

// outdatedGatewayAPICRDs lists the Gateway API CRDs that istiod will ignore. A
// CRD that does not exist is not listed: istiod has nothing to watch either way.
func outdatedGatewayAPICRDs(ctx context.Context, cli client.Client) ([]string, error) {
	names := make([]string, 0, len(istioGatewayAPIMinimumVersions))
	for name := range istioGatewayAPIMinimumVersions {
		names = append(names, name)
	}
	sort.Strings(names)

	var outdated []string
	for _, name := range names {
		minimum := istioGatewayAPIMinimumVersions[name]
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := cli.Get(ctx, client.ObjectKey{Name: name}, crd); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		bundle, ok := crd.Annotations[gatewayAPIBundleVersionAnnotation]
		if !ok {
			outdated = append(outdated, fmt.Sprintf("%s has no %s annotation, Istio needs v%s or newer", name, gatewayAPIBundleVersionAnnotation, minimum))
			continue
		}
		version, err := semver.NewVersion(bundle)
		if err != nil {
			outdated = append(outdated, fmt.Sprintf("%s has bundle version %q, which Istio cannot parse; Istio needs v%s or newer", name, bundle, minimum))
			continue
		}
		// Istio rounds a pre-release up to its release.
		if release, err := version.SetPrerelease(""); err == nil {
			version = &release
		}
		if version.LessThan(minimum) {
			outdated = append(outdated, fmt.Sprintf("%s is at Gateway API %s, Istio needs v%s or newer", name, bundle, minimum))
		}
	}
	return outdated, nil
}

func gatewayAPIWarning(outdated []string) string {
	return "Istio ignores Gateway API CRDs below the version it needs, so routes of these kinds attached to Istio gateways and waypoints have no effect: " +
		strings.Join(outdated, "; ") +
		". Upgrade the Gateway API CRDs, or set crdManagement to Reconcile in the GatewayAPI resource."
}
