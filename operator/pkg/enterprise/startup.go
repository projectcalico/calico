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
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common/discovery"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/intrusiondetection/dpi"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage/eck"
)

// VerifyAPIsExist reports whether the Enterprise CRDs the extension controllers need are installed.
func VerifyAPIsExist(variant operatorv1.ProductVariant, cs kubernetes.Interface) error {
	if !variant.IsEnterprise() {
		return nil
	}

	exist, err := discovery.EnterpriseAPIsExist(cs)
	if err != nil {
		return fmt.Errorf("failed to determine whether the Enterprise APIs are available: %w", err)
	}
	if !exist {
		return fmt.Errorf("the Calico Enterprise CRDs are not installed")
	}
	return nil
}

// VerifyElasticsearch rejects a cluster whose Elasticsearch certificates contradict the
// internal or external mode the operator is configured for.
func VerifyElasticsearch(ctx context.Context, cs kubernetes.Interface, variant operatorv1.ProductVariant, migrating, external bool) error {
	if !variant.IsEnterprise() {
		return nil
	}

	// A migration's final phase has both certificates present, so exclusivity does not hold.
	if migrating {
		return nil
	}

	if external {
		if _, err := cs.CoreV1().Secrets(render.ElasticsearchNamespace).Get(ctx, render.TigeraElasticsearchInternalCertSecret, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("unexpected error encountered when confirming elastic is not currently internal: %w", err)
		}
		return fmt.Errorf("refusing to run: configured as external ES but secret/%s found which suggests internal ES", render.TigeraElasticsearchInternalCertSecret)
	}

	if _, err := cs.CoreV1().Secrets(render.ElasticsearchNamespace).Get(ctx, logstorage.ExternalCertsSecret, metav1.GetOptions{}); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("unexpected error encountered when confirming elastic is not currently external: %w", err)
	}
	return fmt.Errorf("refusing to run: configured as internal ES but secret/%s found which suggests external ES", logstorage.ExternalCertsSecret)
}

// ProtectedNamespaces returns the Enterprise namespaces the operator manages and so
// must not run in itself.
func ProtectedNamespaces() []string {
	return []string{
		render.ElasticsearchNamespace,
		render.IntrusionDetectionNamespace,
		dpi.DeepPacketInspectionNamespace,
		eck.OperatorNamespace,
		render.LogCollectorNamespace,
		render.ManagerNamespace,
		istio.IstioNamespace,
	}
}
