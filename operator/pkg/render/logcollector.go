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

package render

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// This file holds log-collector symbols that must remain in the render package
// because other render components depend on them. The bulk of the log-collector
// (fluent-bit / EKS log-forwarder) rendering lives in pkg/render/logcollector;
// these symbols stay here to avoid a render -> render/logcollector import cycle.
// The logcollector package aliases the constants below for its own use.

const (
	LogCollectorNamespace = "calico-system"

	// FluentBitNodeName / FluentBitNodeWindowsName are the k8s-app label values of the
	// fluent-bit DaemonSet pods, used to select them as a NetworkPolicy source.
	FluentBitNodeName        = "calico-fluent-bit"
	FluentBitNodeWindowsName = "calico-fluent-bit-windows"

	// FluentBitInputService is the Service fronting fluent-bit's HTTP input, which
	// Manager/Voltron egresses to when forwarding non-cluster-host logs.
	FluentBitInputService = "calico-fluent-bit-http-input"

	EKSLogForwarderName = "eks-log-forwarder"

	// SplunkFluentBitSecretCertificateKey is the key under which the Splunk CA cert is
	// mounted; the shared TrustedBundleVolume below also exposes the trusted bundle at
	// this path, so it lives here alongside that helper.
	SplunkFluentBitSecretCertificateKey = "ca.pem"

	// Linseed token volume mounting constants, shared by several components
	// (compliance, apiserver, intrusion detection, policy recommendation, fluent-bit).
	LinseedTokenVolumeName = "linseed-token"
	LinseedTokenKey        = "token"
	LinseedTokenSubPath    = "token"
	LinseedTokenSecret     = "%s-tigera-linseed-token"
	LinseedVolumeMountPath = "/var/run/secrets/tigera.io/linseed/"
	LinseedTokenPath       = "/var/run/secrets/tigera.io/linseed/token"
)

// FluentBitSourceEntityRule selects the fluent-bit pods as a NetworkPolicy source.
var FluentBitSourceEntityRule = v3.EntityRule{
	NamespaceSelector: fmt.Sprintf("name == '%s'", LogCollectorNamespace),
	Selector:          networkpolicy.KubernetesAppSelector(FluentBitNodeName, FluentBitNodeWindowsName),
}

// EKSLogForwarderEntityRule selects the EKS log-forwarder pods as a NetworkPolicy source.
var EKSLogForwarderEntityRule = networkpolicy.CreateSourceEntityRule(LogCollectorNamespace, EKSLogForwarderName)

// TrustedBundleVolume mounts the trusted CA bundle under the standard name plus a few
// legacy/compatibility paths (including the Elastic and Splunk cert keys). It is shared
// by Dex and the log-collector components.
func TrustedBundleVolume(bundle certificatemanagement.TrustedBundle) corev1.Volume {
	volume := bundle.Volume()
	// We mount the bundle under two names; the standard name and the name for the expected elastic cert.
	volume.ConfigMap.Items = []corev1.KeyToPath{
		{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: certificatemanagement.TrustedCertConfigMapKeyName},
		//nolint:staticcheck // Ignore SA1019 deprecated
		{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: certificatemanagement.LegacyTrustedCertConfigMapKeyName},
		{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: SplunkFluentBitSecretCertificateKey},
		{Key: certificatemanagement.RHELRootCertificateBundleName, Path: certificatemanagement.RHELRootCertificateBundleName},
	}
	return volume
}
