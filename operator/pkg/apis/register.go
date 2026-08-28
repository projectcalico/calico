// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package apis

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	envoy "github.com/envoyproxy/gateway/api/v1alpha1"
	netattachv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	configv1 "github.com/openshift/api/config/v1"
	ocsv1 "github.com/openshift/api/security/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render/istio"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	aggregator "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
	gateway "sigs.k8s.io/gateway-api/apis/v1"
	csisecret "sigs.k8s.io/secrets-store-csi-driver/apis/v1"
)

// AddToSchemes may be used to add all resources defined in the project to a Scheme
var (
	AddToSchemes runtime.SchemeBuilder
)

// AddToScheme adds all Resources to the Scheme
func AddToScheme(s *runtime.Scheme, v3 bool) error {
	if err := AddToSchemes.AddToScheme(s); err != nil {
		return err
	}
	return calicoSchemeBuilder(v3)(s)
}

func init() {
	AddToSchemes = append(AddToSchemes, configv1.Install)
	AddToSchemes = append(AddToSchemes, aggregator.AddToScheme)
	AddToSchemes = append(AddToSchemes, apiextensions.AddToScheme)
	AddToSchemes = append(AddToSchemes, ocsv1.AddToScheme)
	AddToSchemes = append(AddToSchemes, esv1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, kbv1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, policyv1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, policyv1beta1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, gateway.Install)
	AddToSchemes = append(AddToSchemes, envoy.AddToScheme)
	// EnvoyFilter is a hand-rolled shim type defined in pkg/render/istio (used
	// for waypoint L7 logging); register it centrally like the other types.
	AddToSchemes = append(AddToSchemes, istio.AddEnvoyFilterToScheme)
	AddToSchemes = append(AddToSchemes, csisecret.AddToScheme)
	AddToSchemes = append(AddToSchemes, operatorv1.AddToScheme)
	AddToSchemes = append(AddToSchemes, admissionregistrationv1.AddToScheme)
	AddToSchemes = append(AddToSchemes, monitoringv1.AddToScheme)
	AddToSchemes = append(AddToSchemes, corev1.AddToScheme)
	AddToSchemes = append(AddToSchemes, rbacv1.AddToScheme)
	AddToSchemes = append(AddToSchemes, appsv1.AddToScheme)
	// Istio's rendered Helm charts include a HorizontalPodAutoscaler, so the
	// scheme needs autoscaling/v2 for the universal deserializer to decode them.
	AddToSchemes = append(AddToSchemes, autoscalingv2.AddToScheme)
	AddToSchemes = append(AddToSchemes, batchv1.AddToScheme)
	AddToSchemes = append(AddToSchemes, storagev1.AddToScheme)
	AddToSchemes = append(AddToSchemes, certificatesv1.AddToScheme)
	AddToSchemes = append(AddToSchemes, networkingv1.AddToScheme)
	AddToSchemes = append(AddToSchemes, netattachv1.AddToScheme)
}

func calicoSchemeBuilder(useV3 bool) func(*runtime.Scheme) error {
	// We need to register the correct API groups based on the backing API group in use. This
	// is a bit tricky, because some types are always in the same group, while others vary based on
	// whether we're using the crd.projectcalico.org or projectcalico.org API group.
	return func(scheme *runtime.Scheme) error {
		// Handle types that are always in the projectcalico.org/v3 API group.
		v3Types := []runtime.Object{
			&v3.DeepPacketInspection{},
			&v3.DeepPacketInspectionList{},
			&v3.GlobalNetworkPolicy{},
			&v3.GlobalNetworkPolicyList{},
			&v3.GlobalReportType{},
			&v3.GlobalReportTypeList{},
			&v3.GlobalAlert{},
			&v3.GlobalAlertList{},
			&v3.GlobalAlertTemplate{},
			&v3.GlobalAlertTemplateList{},
			&v3.HostEndpoint{},
			&v3.HostEndpointList{},
			&v3.IPAMConfiguration{},
			&v3.IPAMConfigurationList{},
			&v3.LicenseKey{},
			&v3.LicenseKeyList{},
			&v3.NetworkPolicy{},
			&v3.NetworkPolicyList{},
			&v3.NetworkSet{},
			&v3.NetworkSetList{},
			&v3.PolicyRecommendationScope{},
			&v3.PolicyRecommendationScopeList{},
			&v3.Tier{},
			&v3.TierList{},
			&v3.UISettings{},
			&v3.UISettingsGroup{},
			&v3.UISettingsGroupList{},
			&v3.UISettingsList{},
		}

		// Handle types that are always in the crd.projectcalico.org/v1 API group.
		v1Types := []runtime.Object{}

		// Handle types that vary based on backing API group.
		variableTypes := []runtime.Object{
			&v3.BGPConfiguration{},
			&v3.BGPConfigurationList{},
			&v3.ClusterInformation{},
			&v3.ClusterInformationList{},
			&v3.ExternalNetwork{},
			&v3.ExternalNetworkList{},
			&v3.FelixConfiguration{},
			&v3.FelixConfigurationList{},
			&v3.IPPool{},
			&v3.IPPoolList{},
			&v3.KubeControllersConfiguration{},
			&v3.KubeControllersConfigurationList{},
		}
		if useV3 {
			log.Info("Registering Calico CRD types with projectcalico.org/v3 API group")
			v3Types = append(v3Types, variableTypes...)
		} else {
			log.Info("Registering Calico CRD types with crd.projectcalico.org/v1 API group")
			v1Types = append(v1Types, variableTypes...)
		}

		// Register types with the crd.projectcalico.org API group.
		v1GV := schema.GroupVersion{Group: "crd.projectcalico.org", Version: "v1"}
		scheme.AddKnownTypes(v1GV, v1Types...)
		metav1.AddToGroupVersion(scheme, v1GV)

		// Register types with the projectcalico.org API group.
		v3GV := schema.GroupVersion{Group: "projectcalico.org", Version: "v3"}
		scheme.AddKnownTypes(v3GV, v3Types...)
		metav1.AddToGroupVersion(scheme, v3GV)

		return nil
	}
}
