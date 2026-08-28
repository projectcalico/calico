package kibana

import (
	"fmt"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	httpsEndpoint     = "https://tigera-secure-es-gateway-http.tigera-elasticsearch.svc:5601"
	httpsFQDNEndpoint = "https://tigera-secure-es-gateway-http.tigera-elasticsearch.svc.%s:5601"
)

// HTTPSEndpoint returns the full endpoint for the Kibana service. For
// Windows, the FQDN endpoint is returned.
func HTTPSEndpoint(osType rmeta.OSType, clusterDomain string) string {
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(httpsFQDNEndpoint, clusterDomain)
	}
	return httpsEndpoint
}
