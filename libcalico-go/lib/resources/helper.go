// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package resources

import (
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit"
)

const (
	v1                      = "v1"
	grpVersionProjectcalico = "projectcalico.org/v3"
	grpVersionK8sNetworking = "networking.k8s.io/v1"
	grpVersionExtensions    = "extensions/v1beta1"
	isNamespaced            = true
	isNotNamespaced         = false
	isTieredPolicy          = true
	isNotTieredPolicy       = false
)

var (
	TypeCalicoGlobalNetworkPolicies           = metav1.TypeMeta{APIVersion: grpVersionProjectcalico, Kind: apiv3.KindGlobalNetworkPolicy}
	TypeCalicoStagedGlobalNetworkPolicies     = metav1.TypeMeta{APIVersion: grpVersionProjectcalico, Kind: apiv3.KindStagedGlobalNetworkPolicy}
	TypeCalicoGlobalNetworkSets               = metav1.TypeMeta{APIVersion: grpVersionProjectcalico, Kind: apiv3.KindGlobalNetworkSet}
	TypeCalicoNetworkSets                     = metav1.TypeMeta{APIVersion: grpVersionProjectcalico, Kind: apiv3.KindNetworkSet}
	TypeCalicoHostEndpoints                   = metav1.TypeMeta{APIVersion: grpVersionProjectcalico, Kind: apiv3.KindHostEndpoint}
	TypeCalicoNetworkPolicies                 = metav1.TypeMeta{APIVersion: grpVersionProjectcalico, Kind: apiv3.KindNetworkPolicy}
	TypeCalicoStagedNetworkPolicies           = metav1.TypeMeta{APIVersion: grpVersionProjectcalico, Kind: apiv3.KindStagedNetworkPolicy}
	TypeCalicoStagedKubernetesNetworkPolicies = metav1.TypeMeta{APIVersion: grpVersionProjectcalico, Kind: apiv3.KindStagedKubernetesNetworkPolicy}
	TypeCalicoTiers                           = metav1.TypeMeta{APIVersion: grpVersionProjectcalico, Kind: apiv3.KindTier}
	TypeK8sServices                           = metav1.TypeMeta{APIVersion: v1, Kind: "Service"}
	TypeK8sEndpoints                          = metav1.TypeMeta{APIVersion: v1, Kind: "Endpoints"}
	TypeK8sNamespaces                         = metav1.TypeMeta{APIVersion: v1, Kind: "Namespace"}
	TypeK8sNetworkPolicies                    = metav1.TypeMeta{APIVersion: grpVersionK8sNetworking, Kind: "NetworkPolicy"}
	TypeK8sPods                               = metav1.TypeMeta{APIVersion: v1, Kind: "Pod"}
	TypeK8sServiceAccounts                    = metav1.TypeMeta{APIVersion: v1, Kind: "ServiceAccount"}
	TypeK8sStatus                             = metav1.TypeMeta{APIVersion: v1, Kind: "Status"}

	// Legacy types.
	TypeK8sNetworkPoliciesExtensions = metav1.TypeMeta{APIVersion: grpVersionExtensions, Kind: "NetworkPolicy"}
)

type ResourceHelper interface {
	TypeMeta() metav1.TypeMeta
	NewResource() Resource
	NewResourceList() ResourceList
	Deprecated() []metav1.TypeMeta
	Plural() string
	RbacPlural() string
	GetAuditEventsSelection() *apiv3.AuditEventsSelection
	IsNamespaced() bool
	IsTieredPolicy() bool
	Group() string
}

// GetTypeMeta extracts the group version kind from the resource unless
//
//	it is using a deprecated apiVersion
func GetTypeMeta(res Resource) metav1.TypeMeta {
	gvk := res.GetObjectKind().GroupVersionKind()
	tm := metav1.TypeMeta{Kind: gvk.Kind, APIVersion: gvk.GroupVersion().String()}
	h := resourceHelpersByTypeMap[tm]
	if h == nil {
		return tm
	}
	return h.tm
}

// GetResourceHelperByTypeMeta returns the requested ResourceHelper, or nil if not supported.
func GetResourceHelperByTypeMeta(tm metav1.TypeMeta) ResourceHelper {
	if rh, ok := resourceHelpersByTypeMap[tm]; ok {
		return rh
	}
	return nil
}

// GetResourceHelperByObjectRef returns the appropriate ResourceHelper from an audit log ObjectRef. The audit log
// ObjectRef uses the lowercase plural form of the resource kind.
func GetResourceHelperByObjectRef(reference auditv1.ObjectReference) ResourceHelper {
	a := apiv3.AuditResource{
		Resource:   reference.Resource,
		APIVersion: reference.APIVersion,
		APIGroup:   reference.APIGroup,
	}
	if rh, ok := resourceHelpersByAuditMap[a]; ok {
		return rh
	}
	return nil
}

// GetAllResourceHelpers returns a list of all supported ResourceHelpers.
func GetAllResourceHelpers() []ResourceHelper {
	rhs := make([]ResourceHelper, len(resourceHelpers))
	for i, rh := range resourceHelpers {
		rhs[i] = rh
	}
	return rhs
}

// NewResource returns a new instance of the requested resource type.
func NewResource(tm metav1.TypeMeta) Resource {
	helper := resourceHelpersByTypeMap[tm]
	if helper == nil {
		return nil
	}
	return helper.NewResource()
}

// NewResourceList returns a new instance of the requested resource type list.
func NewResourceList(tm metav1.TypeMeta) ResourceList {
	helper := resourceHelpersByTypeMap[tm]
	if helper == nil {
		return nil
	}
	return helper.NewResourceList()
}

type resourceHelper struct {
	tm             metav1.TypeMeta
	resource       Resource
	resourceList   ResourceList
	deprecated     []metav1.TypeMeta
	plural         string
	isNamespaced   bool
	isTieredPolicy bool
}

func (h *resourceHelper) TypeMeta() metav1.TypeMeta {
	return h.tm
}

func (h *resourceHelper) NewResource() Resource {
	r := h.resource.DeepCopyObject().(Resource)
	r.GetObjectKind().SetGroupVersionKind(h.tm.GroupVersionKind())
	return r
}

func (h *resourceHelper) NewResourceList() ResourceList {
	rl := h.resourceList.DeepCopyObject().(ResourceList)
	rl.GetObjectKind().SetGroupVersionKind(h.tm.GroupVersionKind())
	return rl
}

func (h *resourceHelper) Deprecated() []metav1.TypeMeta {
	return h.deprecated
}

func (h *resourceHelper) GetAuditEventsSelection() *apiv3.AuditEventsSelection {
	return &apiv3.AuditEventsSelection{
		Resources: h.getAuditResources(),
	}
}

func (h *resourceHelper) Plural() string {
	return h.plural
}

func (h *resourceHelper) RbacPlural() string {
	if h.isTieredPolicy {
		return "tier." + h.plural
	}
	return h.plural
}

func (h *resourceHelper) Group() string {
	tm := &h.tm
	return tm.GroupVersionKind().Group
}

func (h *resourceHelper) getAuditResources() []apiv3.AuditResource {
	a := []apiv3.AuditResource{{
		Resource:   h.plural,
		APIVersion: h.tm.GroupVersionKind().Version,
		APIGroup:   h.tm.GroupVersionKind().Group,
	}}
	for _, dep := range h.Deprecated() {
		a = append(a, apiv3.AuditResource{
			Resource:   h.plural,
			APIVersion: dep.GroupVersionKind().Version,
			APIGroup:   dep.GroupVersionKind().Group,
		})
	}
	return a
}

func (h *resourceHelper) IsNamespaced() bool {
	return h.isNamespaced
}

func (h *resourceHelper) IsTieredPolicy() bool {
	return h.isTieredPolicy
}

// TODO(rlb): We are now using the AAPIS interface in preference to the Calico API directly. This means there is a
//
//	discrepancy between the resource type structs. We should fix that up by moving the autogenerated
//	API resources into libcalico-go(-private) ... that way *everything* can use the same set.
var (
	resourceHelpersByTypeMap  = map[metav1.TypeMeta]*resourceHelper{}
	resourceHelpersByAuditMap = map[apiv3.AuditResource]*resourceHelper{}
	allAuditResources         = []apiv3.AuditResource{}
	allTypeMeta               = []metav1.TypeMeta{}
	resourceHelpers           = []*resourceHelper{
		{
			TypeK8sPods,
			&corev1.Pod{},
			&corev1.PodList{},
			[]metav1.TypeMeta{},
			"pods",
			isNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeK8sNamespaces,
			&corev1.Namespace{},
			&corev1.NamespaceList{},
			[]metav1.TypeMeta{},
			"namespaces",
			isNotNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeK8sServiceAccounts,
			&corev1.ServiceAccount{},
			&corev1.ServiceAccountList{},
			[]metav1.TypeMeta{},
			"serviceaccounts",
			isNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeK8sEndpoints,
			&corev1.Endpoints{},
			&corev1.EndpointsList{},
			[]metav1.TypeMeta{},
			"endpoints",
			isNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeK8sNetworkPolicies,
			&networkingv1.NetworkPolicy{},
			&networkingv1.NetworkPolicyList{},
			[]metav1.TypeMeta{TypeK8sNetworkPoliciesExtensions},
			"networkpolicies",
			isNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeCalicoTiers,
			&apiv3.Tier{},
			&apiv3.TierList{},
			[]metav1.TypeMeta{},
			"tiers",
			isNotNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeCalicoHostEndpoints,
			&apiv3.HostEndpoint{},
			&apiv3.HostEndpointList{},
			[]metav1.TypeMeta{},
			"hostendpoints",
			isNotNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeCalicoGlobalNetworkSets,
			&apiv3.GlobalNetworkSet{},
			&apiv3.GlobalNetworkSetList{},
			[]metav1.TypeMeta{},
			"globalnetworksets",
			isNotNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeCalicoNetworkSets,
			&apiv3.NetworkSet{},
			&apiv3.NetworkSetList{},
			[]metav1.TypeMeta{},
			"networksets",
			isNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeCalicoNetworkPolicies,
			&apiv3.NetworkPolicy{},
			&apiv3.NetworkPolicyList{},
			[]metav1.TypeMeta{},
			"networkpolicies",
			isNamespaced,
			isTieredPolicy,
		},
		{
			TypeCalicoGlobalNetworkPolicies,
			&apiv3.GlobalNetworkPolicy{},
			&apiv3.GlobalNetworkPolicyList{},
			[]metav1.TypeMeta{},
			"globalnetworkpolicies",
			isNotNamespaced,
			isTieredPolicy,
		},
		{
			TypeCalicoStagedNetworkPolicies,
			&apiv3.StagedNetworkPolicy{},
			&apiv3.StagedNetworkPolicyList{},
			[]metav1.TypeMeta{},
			"stagednetworkpolicies",
			isNamespaced,
			isTieredPolicy,
		},
		{
			TypeCalicoStagedKubernetesNetworkPolicies,
			&apiv3.StagedKubernetesNetworkPolicy{},
			&apiv3.StagedKubernetesNetworkPolicyList{},
			[]metav1.TypeMeta{},
			"stagedkubernetesnetworkpolicies",
			isNamespaced,
			isNotTieredPolicy,
		},
		{
			TypeCalicoStagedGlobalNetworkPolicies,
			&apiv3.StagedGlobalNetworkPolicy{},
			&apiv3.StagedGlobalNetworkPolicyList{},
			[]metav1.TypeMeta{},
			"stagedglobalnetworkpolicies",
			isNotNamespaced,
			isTieredPolicy,
		},
	}
)

func init() {
	// Build up the lookup maps by TypeMeta and by AuditResource query.
	for _, rh := range resourceHelpers {
		resourceHelpersByTypeMap[rh.tm] = rh
		allTypeMeta = append(allTypeMeta, rh.tm)

		for _, dep := range rh.deprecated {
			resourceHelpersByTypeMap[dep] = rh
			allTypeMeta = append(allTypeMeta, dep)
		}

		for _, a := range rh.getAuditResources() {
			resourceHelpersByAuditMap[a] = rh
		}
	}
}
