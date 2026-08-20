// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package utils

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	egOwningGatewayNameLabel      = "gateway.envoyproxy.io/owning-gateway-name"
	egOwningGatewayNamespaceLabel = "gateway.envoyproxy.io/owning-gateway-namespace"

	gatewayProxyReadyTimeout = 3 * time.Minute
	gatewayProxyPollInterval = 5 * time.Second
)

// GatewayProxyBaseURL port-forwards to the Envoy Gateway proxy Service that
// fronts the given Gateway and returns a local base URL plus a stop function
// the caller must invoke when done.
//
// The proxy Service is found by the Envoy Gateway owning-Gateway labels rather
// than by a fixed namespace: the proxy runs in the Gateway's own namespace or
// a dedicated one depending on the render, and the Service is named after the
// Gateway. The Gateway's external address is never assigned on a cluster
// without a cloud LoadBalancer, so this deliberately port-forwards to the
// ClusterIP instead of waiting for Programmed=True.
//
// With https true the HTTPS port is preferred and the returned URL uses the
// https scheme; otherwise the HTTP port. A port matches on Envoy Gateway's own
// name for it, "<protocol>-<port>", or on the default port number. Either way
// the first TCP port is the fallback.
func GatewayProxyBaseURL(ctx context.Context, clientset kubernetes.Interface, gwNamespace, gwName string, https bool) (string, func()) {
	selector := fmt.Sprintf("%s=%s,%s=%s",
		egOwningGatewayNameLabel, gwName,
		egOwningGatewayNamespaceLabel, gwNamespace)

	preferredProto, preferredPort := "http", int32(80)
	scheme := "http"
	if https {
		preferredProto, preferredPort = "https", 443
		scheme = "https"
	}

	var svcNS, svcName string
	var remotePort int32
	gomega.Eventually(func() error {
		listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		// Empty namespace lists across all namespaces; see above.
		svcList, err := clientset.CoreV1().Services("").List(listCtx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return fmt.Errorf("failed to list proxy Services: %w", err)
		}
		for _, svc := range svcList.Items {
			if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
				continue
			}
			var chosen int32
			for _, p := range svc.Spec.Ports {
				if p.Protocol != "" && p.Protocol != corev1.ProtocolTCP {
					continue
				}
				// Envoy Gateway names the port "<protocol>-<port>", so match
				// the protocol prefix rather than the bare scheme, which never
				// equals the name. Without this a TLS listener on a port other
				// than 443 falls through to the fallback below and can hand
				// back a plaintext port behind an https:// URL.
				if strings.HasPrefix(p.Name, preferredProto+"-") || p.Port == preferredPort {
					chosen = p.Port
					break
				}
				if chosen == 0 {
					chosen = p.Port
				}
			}
			if chosen != 0 {
				svcNS, svcName, remotePort = svc.Namespace, svc.Name, chosen
				return nil
			}
		}
		return fmt.Errorf("no Envoy Gateway proxy Service with a ClusterIP+TCP port for Gateway %s/%s yet", gwNamespace, gwName)
	}).WithTimeout(gatewayProxyReadyTimeout).WithPolling(gatewayProxyPollInterval).Should(
		gomega.Succeed(), "Envoy Gateway proxy Service for Gateway %s/%s should be provisioned", gwNamespace, gwName)

	stopCh := make(chan time.Time)
	kc := &Kubectl{}
	localPort, err := kc.PortForward(svcNS, "svc/"+svcName, fmt.Sprintf("%d", remotePort), "", stopCh)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to port-forward to Gateway proxy Service %s/%s", svcNS, svcName)

	stop := func() { close(stopCh) }
	return fmt.Sprintf("%s://127.0.0.1:%d", scheme, localPort), stop
}
