// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package elasticsearch

import (
	"fmt"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	httpsEndpoint     = "https://tigera-secure-es-gateway-http.%s.svc:9200"
	httpsFQDNEndpoint = "https://tigera-secure-es-gateway-http.%s.svc.%s:9200"
)

func LinseedEndpoint(osType rmeta.OSType, clusterDomain, namespace string, isManagedCluster bool, isFluentBit bool) string {
	switch {
	// In a managed cluster, all Elasticsearch requests to Linseed are redirected via the Guardian service.
	// Clients using the Linseed client are automatically configured with the correct SNI for certificate validation.
	// Since Fluent Bit doesn't use the Linseed client, we expose an external service named "tigera-linseed" that redirects to Guardian.
	// The Linseed certificate is already configured to accept connections with SNI set to "tigera-linseed".
	case isManagedCluster && isFluentBit:
		return "https://tigera-linseed"

	// Non-Fluent-Bit components in the managed cluster forward traffic to Guardian
	case isManagedCluster && osType == rmeta.OSTypeWindows:
		return fmt.Sprintf("https://guardian.calico-system.svc.%s", clusterDomain)
	case isManagedCluster:
		return "https://guardian.calico-system.svc"
	// Linseed URL used by components in standalone and management cluster.
	case osType == rmeta.OSTypeWindows:
		return fmt.Sprintf("https://tigera-linseed.%s.svc.%s", namespace, clusterDomain)
	default:
		return fmt.Sprintf("https://tigera-linseed.%s.svc", namespace)
	}
}

// GatewayEndpoint returns the endpoint for the Elasticsearch service. For
// Windows, the FQDN endpoint is returned.
func GatewayEndpoint(osType rmeta.OSType, clusterDomain, namespace string) string {
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(httpsFQDNEndpoint, namespace, clusterDomain)
	}
	return fmt.Sprintf(httpsEndpoint, namespace)
}

// Deprecated - does not support multi-tenancy. Use GatewayEndpoint instead.
func HTTPSEndpoint(osType rmeta.OSType, clusterDomain string) string {
	return GatewayEndpoint(osType, clusterDomain, "tigera-elasticsearch")
}

// ECKElasticEndpoint returns the URL of the Elasticsearch provisioned by the ECK operator. This
// endpoint is only valid when using internal elasticsearch.
func ECKElasticEndpoint() string {
	return "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
}
