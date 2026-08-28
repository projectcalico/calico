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

package metrics

import (
	"context"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("metrics_collector")

var (
	componentStatusDesc = prometheus.NewDesc(
		"tigera_operator_component_status",
		"TigeraStatus conditions for operator-managed components. 1 = true, 0 = false.",
		[]string{"component", "condition"},
		nil,
	)

	tlsCertExpiryDesc = prometheus.NewDesc(
		"tigera_operator_tls_certificate_expiry_timestamp_seconds",
		"Unix timestamp of certificate expiry for operator-managed TLS secrets.",
		[]string{"name", "namespace", "issuer"},
		nil,
	)

	licenseExpiryDesc = prometheus.NewDesc(
		"tigera_operator_license_expiry_timestamp_seconds",
		"Unix timestamp of Tigera license expiry.",
		[]string{"package"},
		nil,
	)

	licenseValidDesc = prometheus.NewDesc(
		"tigera_operator_license_valid",
		"Whether the Tigera license is valid (including grace period). 1 = valid, 0 = invalid.",
		[]string{"package"},
		nil,
	)
)

// OperatorCollector implements prometheus.Collector and exposes custom operator metrics.
type OperatorCollector struct {
	client           client.Client
	licenseAvailable bool
}

// NewOperatorCollector creates a new OperatorCollector. Set licenseAvailable to true
// when the LicenseKey CRD exists (Calico Enterprise).
func NewOperatorCollector(c client.Client, licenseAvailable bool) *OperatorCollector {
	return &OperatorCollector{client: c, licenseAvailable: licenseAvailable}
}

// Describe implements prometheus.Collector.
func (c *OperatorCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- componentStatusDesc
	ch <- tlsCertExpiryDesc
	ch <- licenseExpiryDesc
	ch <- licenseValidDesc
}

// Collect implements prometheus.Collector.
func (c *OperatorCollector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()
	c.collectComponentStatus(ctx, ch)
	c.collectTLSCertExpiry(ctx, ch)
	if c.licenseAvailable {
		c.collectLicense(ctx, ch)
	}
}

func (c *OperatorCollector) collectComponentStatus(ctx context.Context, ch chan<- prometheus.Metric) {
	statusList := &operatorv1.TigeraStatusList{}
	if err := c.client.List(ctx, statusList); err != nil {
		return
	}

	conditions := []operatorv1.StatusConditionType{
		operatorv1.ComponentAvailable,
		operatorv1.ComponentProgressing,
		operatorv1.ComponentDegraded,
	}

	for _, ts := range statusList.Items {
		for _, condType := range conditions {
			val := float64(0)
			for _, cond := range ts.Status.Conditions {
				if cond.Type == condType && cond.Status == operatorv1.ConditionTrue {
					val = 1
					break
				}
			}
			ch <- prometheus.MustNewConstMetric(
				componentStatusDesc,
				prometheus.GaugeValue,
				val,
				ts.Name,
				conditionLabel(condType),
			)
		}
	}
}

func conditionLabel(ct operatorv1.StatusConditionType) string {
	return strings.ToLower(string(ct))
}

func (c *OperatorCollector) collectTLSCertExpiry(ctx context.Context, ch chan<- prometheus.Metric) {
	secrets := &corev1.SecretList{}
	if err := c.client.List(ctx, secrets, client.HasLabels{certificatemanagement.SignerLabel}); err != nil {
		return
	}

	for _, s := range secrets.Items {
		expiryStr, ok := s.Annotations[certificatemanagement.ExpiryAnnotation]
		if !ok {
			continue
		}

		expiry, err := time.Parse(certificatemanagement.ExpiryFormat, expiryStr)
		if err != nil {
			log.V(2).Info("Skipping secret with unparseable expiry annotation", "secret", s.Name, "namespace", s.Namespace, "error", err)
			continue
		}

		issuer := s.Annotations[certificatemanagement.IssuerAnnotation]

		ch <- prometheus.MustNewConstMetric(
			tlsCertExpiryDesc,
			prometheus.GaugeValue,
			float64(expiry.Unix()),
			s.Name,
			s.Namespace,
			issuer,
		)
	}
}

func (c *OperatorCollector) collectLicense(ctx context.Context, ch chan<- prometheus.Metric) {
	license, err := utils.FetchLicenseKey(ctx, c.client)
	if err != nil {
		// License not yet available or transient read error. Skip gracefully.
		return
	}

	pkg := string(license.Status.Package)
	if pkg == "" {
		pkg = "Enterprise"
	}

	if !license.Status.Expiry.IsZero() {
		ch <- prometheus.MustNewConstMetric(
			licenseExpiryDesc,
			prometheus.GaugeValue,
			float64(license.Status.Expiry.Unix()),
			pkg,
		)
	}

	gracePeriod := utils.ParseGracePeriod(license.Status.GracePeriod)
	licenseStatus := utils.GetLicenseStatus(license, gracePeriod)
	valid := float64(1)
	if licenseStatus == utils.LicenseStatusExpired {
		valid = 0
	}

	ch <- prometheus.MustNewConstMetric(
		licenseValidDesc,
		prometheus.GaugeValue,
		valid,
		pkg,
	)
}
