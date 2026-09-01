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

package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	fakeapiregclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	"k8s.io/utils/ptr"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/rawcrdclient"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	libtestutils "github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

// seedNamespace holds the namespaced v1 resources, mirroring the namespace the
// kind migration test seeds into.
const seedNamespace = "migration-test"

// TestLifecycle_RealV1CRDs migrates real v1 CRDs seeded as the API server
// stores them. Cleanup deletes those CRDs, so it reinstalls them on entry.
func TestLifecycle_RealV1CRDs(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	h := newFVHelper(t, g, ctx)

	ensureV1CRDs(t, g)
	createNamespace(t, ctx, g, seedNamespace)

	bc, err := k8s.NewKubeClientForConfig(fvTestEnv.RestConfig, fvTestEnv.K8sClient, resources.BackingAPIGroupV1, false)
	g.Expect(err).NotTo(HaveOccurred())

	raw, err := rawcrdclient.New(fvTestEnv.RestConfig, false)
	g.Expect(err).NotTo(HaveOccurred())

	seed := seedV1CRDs(t, ctx, g, raw, bc)

	fakeAPIReg := fakeapiregclient.NewSimpleClientset(newAggregatedAPIServiceObj())
	startRealBackendController(t, ctx, bc, fakeAPIReg)
	createMigrationCR(t, ctx)
	t.Cleanup(func() { cleanupV1SeedResources(t, ctx) })

	// The migration runs unattended here; wait for it to converge.
	g.Eventually(func(g Gomega) {
		newFVHelper(t, g, ctx).expectPhase(migrationv1.DatastoreMigrationPhaseConverged)
	}, 60*time.Second, 250*time.Millisecond).Should(Succeed())

	// Tiers migrate with the default tier's order normalised by the v3 API.
	defaultTier := &apiv3.Tier{}
	h.getV3Resource("default", defaultTier)
	g.Expect(defaultTier.Spec.Order).To(Equal(ptr.To(apiv3.DefaultTierOrder)))

	securityTier := &apiv3.Tier{}
	h.getV3Resource("security", securityTier)
	g.Expect(securityTier.Spec.Order).To(Equal(ptr.To(float64(200))))

	// Default-tier policies lose the stored "default." prefix; other tiers keep theirs.
	denyAll := &apiv3.GlobalNetworkPolicy{}
	h.getV3Resource("test-deny-all", denyAll)
	g.Expect(denyAll.Spec.Tier).To(Equal("default"))
	g.Expect(fvRTClient.Get(ctx, types.NamespacedName{Name: "default.test-deny-all"}, &apiv3.GlobalNetworkPolicy{})).
		To(MatchError(kerrors.IsNotFound, "not found"), "the stored name should not have been migrated verbatim")

	allowDNS := &apiv3.GlobalNetworkPolicy{}
	h.getV3Resource("security.test-allow-dns", allowDNS)
	g.Expect(allowDNS.Spec.Tier).To(Equal("security"))

	allowWeb := &apiv3.NetworkPolicy{}
	g.Expect(fvRTClient.Get(ctx, types.NamespacedName{Name: "test-allow-web", Namespace: seedNamespace}, allowWeb)).To(Succeed())

	hep := &apiv3.HostEndpoint{}
	h.getV3Resource("test-hep", hep)
	g.Expect(hep.Spec.InterfaceName).To(Equal("eth0"))

	gns := &apiv3.GlobalNetworkSet{}
	h.getV3Resource("test-external-ips", gns)
	g.Expect(gns.Spec.Nets).To(ConsistOf("198.51.100.0/24", "203.0.113.0/24"))

	ns := &apiv3.NetworkSet{}
	g.Expect(fvRTClient.Get(ctx, types.NamespacedName{Name: "test-trusted-ips", Namespace: seedNamespace}, ns)).To(Succeed())

	peer := &apiv3.BGPPeer{}
	h.getV3Resource("test-peer", peer)
	g.Expect(peer.Spec.PeerIP).To(Equal("10.0.0.100"))

	// A Calico owner's UID changes when the owner is migrated, so it is remapped.
	g.Expect(allowDNS.OwnerReferences).To(HaveLen(1))
	g.Expect(allowDNS.OwnerReferences[0].Kind).To(Equal("Tier"))
	g.Expect(allowDNS.OwnerReferences[0].UID).To(Equal(securityTier.UID))
	g.Expect(allowDNS.OwnerReferences[0].UID).NotTo(Equal(seed.securityTierV1UID))

	// A native Kubernetes owner is not migrated, so its UID is copied as-is.
	g.Expect(ns.OwnerReferences).To(HaveLen(1))
	g.Expect(ns.OwnerReferences[0].Kind).To(Equal("Namespace"))
	g.Expect(ns.OwnerReferences[0].UID).To(Equal(seed.namespaceUID))

	// Drive to Complete, then delete the CR and check the finalizer removes v1 CRDs.
	h.createReadyCalicoNodeDS()
	g.Eventually(func(g Gomega) {
		newFVHelper(t, g, ctx).expectPhase(migrationv1.DatastoreMigrationPhaseComplete)
	}, 30*time.Second, 250*time.Millisecond).Should(Succeed())

	dm := h.getMigration()
	g.Expect(fvRTClient.Delete(ctx, dm)).To(Succeed())

	g.Eventually(func(g Gomega) {
		err := fvRTClient.Get(ctx, dmKey, &migrationv1.DatastoreMigration{})
		g.Expect(kerrors.IsNotFound(err)).To(BeTrue(), "CR should be deleted after cleanup, got: %v", err)
		g.Expect(describeV1CRDs(ctx)).To(BeEmpty(), "v1 CRDs should have been deleted by the finalizer")
	}, 60*time.Second, 250*time.Millisecond).Should(Succeed())
}

// seededV1State records the values the test can only learn after seeding.
type seededV1State struct {
	namespaceUID      types.UID
	securityTierV1UID types.UID
}

// seedV1CRDs writes the crd.projectcalico.org objects the migration reads.
// Mirrors hack/test/kind/migration/seed-resources.yaml.
func seedV1CRDs(t *testing.T, ctx context.Context, g Gomega, raw rtclient.Client, bc bapi.Client) seededV1State {
	t.Helper()

	seedV1(t, ctx, g, raw, "default", &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: ptr.To(apiv3.DefaultTierOrder), DefaultAction: actionPtr(apiv3.Deny)},
	})
	seedV1(t, ctx, g, raw, "security", &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "security"},
		Spec:       apiv3.TierSpec{Order: ptr.To(float64(200)), DefaultAction: actionPtr(apiv3.Deny)},
	})

	// An owning policy records the UID the API server reports for the Tier, not
	// the underlying CRD's.
	tierKVP, err := bc.Get(ctx, model.ResourceKey{Kind: apiv3.KindTier, Name: "security"}, "")
	g.Expect(err).NotTo(HaveOccurred())
	securityTier, ok := tierKVP.Value.(*apiv3.Tier)
	g.Expect(ok).To(BeTrue())

	nsObj := &corev1.Namespace{}
	g.Expect(fvRTClient.Get(ctx, types.NamespacedName{Name: seedNamespace}, nsObj)).To(Succeed())

	// No name in the metadata annotation, as pre-v3.30 clusters have it. The
	// backend strips the "default." prefix on read.
	denyAll := &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-deny-all"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "default",
			Order:    ptr.To(float64(1000)),
			Selector: "migration-test == 'true'",
			Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
		},
	}
	seedV1WithoutStoredName(t, ctx, g, raw, "default.test-deny-all", denyAll)

	seedV1(t, ctx, g, raw, "security.test-allow-dns", &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "security.test-allow-dns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "projectcalico.org/v3",
					Kind:       "Tier",
					Name:       "security",
					UID:        securityTier.UID,
				},
			},
		},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "security",
			Order:    ptr.To(float64(100)),
			Selector: "migration-test == 'true'",
			Types:    []apiv3.PolicyType{apiv3.PolicyTypeEgress},
			Egress:   []apiv3.Rule{{Action: apiv3.Allow}},
		},
	})

	// The v3 name is in the metadata annotation, as v3.30+ clusters have it.
	// The backend reads it back out.
	seedV1(t, ctx, g, raw, "default.test-allow-web", &apiv3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-allow-web", Namespace: seedNamespace},
		Spec: apiv3.NetworkPolicySpec{
			Tier:     "default",
			Order:    ptr.To(float64(500)),
			Selector: "app == 'web'",
			Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress},
			Ingress:  []apiv3.Rule{{Action: apiv3.Allow}},
		},
	})

	seedV1(t, ctx, g, raw, "test-hep", &apiv3.HostEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "test-hep", Labels: map[string]string{"migration-test": "true"}},
		Spec: apiv3.HostEndpointSpec{
			Node:          "kind-worker",
			InterfaceName: "eth0",
			ExpectedIPs:   []string{"10.0.0.1"},
		},
	})

	seedV1(t, ctx, g, raw, "test-external-ips", &apiv3.GlobalNetworkSet{
		ObjectMeta: metav1.ObjectMeta{Name: "test-external-ips", Labels: map[string]string{"migration-test": "true"}},
		Spec:       apiv3.GlobalNetworkSetSpec{Nets: []string{"198.51.100.0/24", "203.0.113.0/24"}},
	})

	seedV1(t, ctx, g, raw, "test-trusted-ips", &apiv3.NetworkSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-trusted-ips",
			Namespace: seedNamespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Namespace",
					Name:       seedNamespace,
					UID:        nsObj.UID,
				},
			},
		},
		Spec: apiv3.NetworkSetSpec{Nets: []string{"10.0.0.0/8"}},
	})

	seedV1(t, ctx, g, raw, "test-peer", &apiv3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-peer"},
		Spec:       apiv3.BGPPeerSpec{PeerIP: "10.0.0.100", ASNumber: 64512},
	})

	seedV1(t, ctx, g, raw, clusterInfoName, &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
		Spec: apiv3.ClusterInformationSpec{
			ClusterGUID:    "test-guid-12345",
			ClusterType:    "k8s,bgp",
			CalicoVersion:  "v3.30.0",
			DatastoreReady: ptr.To(true),
		},
	})

	return seededV1State{namespaceUID: nsObj.UID, securityTierV1UID: securityTier.UID}
}

// seedV1 encodes a v3 object into v1 form and writes it under its datastore
// name.
func seedV1(t *testing.T, ctx context.Context, g Gomega, raw rtclient.Client, storedName string, obj resources.Resource) {
	t.Helper()
	v1Obj := encodeV1(g, storedName, obj)
	g.ExpectWithOffset(1, raw.Create(ctx, v1Obj)).To(Succeed())
}

// seedV1WithoutStoredName seeds a policy whose metadata annotation carries no
// name, forcing the backend down its "default." prefix-stripping path.
func seedV1WithoutStoredName(t *testing.T, ctx context.Context, g Gomega, raw rtclient.Client, storedName string, obj resources.Resource) {
	t.Helper()
	v1Obj := encodeV1(g, storedName, obj)

	annotations := v1Obj.GetAnnotations()
	meta := &metav1.ObjectMeta{}
	g.ExpectWithOffset(1, json.Unmarshal([]byte(annotations[v1MetadataAnnotation]), meta)).To(Succeed())
	meta.Name = ""
	encoded, err := json.Marshal(meta)
	g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
	annotations[v1MetadataAnnotation] = string(encoded)
	v1Obj.SetAnnotations(annotations)

	g.ExpectWithOffset(1, raw.Create(ctx, v1Obj)).To(Succeed())
}

// v1MetadataAnnotation is where the v1 backend stashes the v3 metadata.
const v1MetadataAnnotation = "projectcalico.org/metadata"

// encodeV1 runs a v3 object through the backend's v3-to-v1 encoding. Without
// the GVK, the encoding drops a policy's stored name.
func encodeV1(g Gomega, storedName string, obj resources.Resource) rtclient.Object {
	gvks, _, err := fvRTClient.Scheme().ObjectKinds(obj)
	g.ExpectWithOffset(2, err).NotTo(HaveOccurred())
	obj.GetObjectKind().SetGroupVersionKind(gvks[0])

	v1Obj, err := resources.ConvertCalicoResourceToK8sResource(obj)
	g.ExpectWithOffset(2, err).NotTo(HaveOccurred())
	v1Obj.GetObjectMeta().SetName(storedName)
	v1Obj.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{})

	rtObj, ok := v1Obj.(rtclient.Object)
	g.ExpectWithOffset(2, ok).To(BeTrue(), "v1 resource does not implement client.Object")
	return rtObj
}

// startRealBackendController starts a migration controller wired to a real
// libcalico-go backend client, with no phase gate.
func startRealBackendController(t *testing.T, ctx context.Context, bc bapi.Client, fakeAPIReg *fakeapiregclient.Clientset) {
	t.Helper()
	ctrl := NewController(ControllerConfig{
		Ctx:                 ctx,
		K8sClient:           fvTestEnv.K8sClient,
		BackendClient:       bc,
		RTClient:            fvRTClient,
		DynamicClient:       fvDynamicClient,
		APIRegClient:        fakeAPIReg.ApiregistrationV1(),
		CRDClient:           fvCRDClient,
		Migrators:           NewMigrators(bc, fvRTClient),
		WaitingPollInterval: 500 * time.Millisecond,
		RestartFunc:         func() {},
	})

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go ctrl.Run(stop)
}

// ensureV1CRDs reinstalls the crd.projectcalico.org CRDs that an earlier test
// deleted. Retries because a terminating CRD cannot be recreated.
func ensureV1CRDs(t *testing.T, g Gomega) {
	t.Helper()
	crdPath := filepath.Join(libtestutils.FindRepoRoot(), "libcalico-go", "config", "crd")
	g.Eventually(func() error {
		_, err := envtest.InstallCRDs(fvTestEnv.RestConfig, envtest.CRDInstallOptions{Paths: []string{crdPath}})
		return err
	}, 60*time.Second, time.Second).Should(Succeed())
}

// describeV1CRDs returns one line per remaining crd.projectcalico.org CRD, naming its
// deletion timestamp, finalizers and conditions so a failure says why the CRD is still there.
func describeV1CRDs(ctx context.Context) ([]string, error) {
	crds, err := fvCRDClient.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, crd := range crds.Items {
		if crd.Spec.Group != "crd.projectcalico.org" {
			continue
		}
		var conditions []string
		for _, c := range crd.Status.Conditions {
			conditions = append(conditions, fmt.Sprintf("%s=%s(%s)", c.Type, c.Status, c.Reason))
		}
		out = append(out, fmt.Sprintf("%s deletionTimestamp=%v finalizers=%v conditions=%v",
			crd.Name, crd.DeletionTimestamp, crd.Finalizers, conditions))
	}
	return out, nil
}

// createNamespace creates a namespace for the namespaced seed resources.
func createNamespace(t *testing.T, ctx context.Context, g Gomega, name string) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	g.Expect(rtclient.IgnoreAlreadyExists(fvRTClient.Create(ctx, ns))).To(Succeed())
}

// cleanupV1SeedResources removes the v3 resources the migration created. The
// v1 CRDs go with the migration's finalizer.
func cleanupV1SeedResources(t *testing.T, ctx context.Context) {
	t.Helper()
	for _, obj := range []rtclient.Object{
		&apiv3.Tier{},
		&apiv3.GlobalNetworkPolicy{},
		&apiv3.HostEndpoint{},
		&apiv3.GlobalNetworkSet{},
		&apiv3.BGPPeer{},
		&apiv3.ClusterInformation{},
	} {
		if err := fvRTClient.DeleteAllOf(ctx, obj); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}

	// DeleteAllOf is namespace-scoped, so the namespaced kinds need the seed
	// namespace naming them explicitly.
	for _, obj := range []rtclient.Object{&apiv3.NetworkPolicy{}, &apiv3.NetworkSet{}} {
		if err := fvRTClient.DeleteAllOf(ctx, obj, rtclient.InNamespace(seedNamespace)); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}
}
