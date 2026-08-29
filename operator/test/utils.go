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

package test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

// ExpectResourceCreated asserts that the given object is created,
// and populates the provided client.Object with the current state of the object
// in the cluster.
func ExpectResourceCreated(c client.Client, obj client.Object) {
	gomega.EventuallyWithOffset(1, func() error {
		return GetResource(c, obj)
	}, 10*time.Second).Should(gomega.BeNil())
}

// ExpectResourceDestroyed asserts that the given object no longer exists.
func ExpectResourceDestroyed(c client.Client, obj client.Object, timeout time.Duration) {
	var err error
	gomega.EventuallyWithOffset(1, func() error {
		err = GetResource(c, obj)
		if errors.IsNotFound(err) || errors.IsGone(err) {
			return nil
		} else if err != nil {
			return err
		} else {
			return fmt.Errorf("%T '%s' should no longer exist", obj, obj.GetName())
		}
	}, timeout).ShouldNot(gomega.HaveOccurred())

	serr, ok := err.(*errors.StatusError)
	gomega.ExpectWithOffset(1, ok).To(gomega.BeTrue(), fmt.Sprintf("error was not StatusError: %v", err))
	gomega.ExpectWithOffset(1, serr.ErrStatus.Code).To(gomega.Equal(int32(404)))
}

// GetResource gets the requested object, populating obj with its contents.
func GetResource(c client.Client, obj client.Object) error {
	k := client.ObjectKey{
		Name:      obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName(),
		Namespace: obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
	}
	return c.Get(context.Background(), k, obj)
}

func GetContainer(containers []corev1.Container, name string) *corev1.Container {
	for _, container := range containers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

// RunOperator runs the provided operator manager in a separate goroutine so that
// the test code isn't blocked. The passed in stop channel can be closed in order to
// stop the execution of the operator.
// The channel returned will be closed when the mgr stops.
func RunOperator(mgr manager.Manager, ctx context.Context) (doneChan chan struct{}) {
	doneChan = make(chan struct{})
	go func() {
		defer ginkgo.GinkgoRecover()
		_ = mgr.Start(ctx)
		close(doneChan)
		// This should not error but it does. Something is not stopping or closing down but
		// this does not cause other errors. This started happening after updating to
		// operator-sdk v1.0.1 from v0.10.0.
		//Expect(err).NotTo(HaveOccurred(), func() string {
		//	var buf bytes.Buffer
		//	pprof.Lookup("goroutine").WriteTo(&buf, 2)
		//	return buf.String()
		//})
	}()
	synced := mgr.GetCache().WaitForCacheSync(ctx)
	gomega.Expect(synced).To(gomega.BeTrue(), "manager cache failed to sync")
	return doneChan
}

func VerifyPublicCert(secret *corev1.Secret, pubKey string, expectedSANs ...string) {
	gomega.Expect(secret.Data).To(gomega.HaveKey(pubKey))
	VerifyCertSANs(secret.Data[pubKey], expectedSANs...)
}

func VerifyCert(secret *corev1.Secret, expectedSANs ...string) {
	gomega.Expect(secret.Data).To(gomega.HaveKey(corev1.TLSPrivateKeyKey))
	gomega.Expect(secret.Data).To(gomega.HaveKey(corev1.TLSCertKey))

	VerifyCertSANs(secret.Data[corev1.TLSCertKey], expectedSANs...)
}

func VerifyCertSANs(certBytes []byte, expectedSANs ...string) {
	pemBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	gomega.Expect(err).To(gomega.BeNil(), "Error parsing bytes from secret into certificate")
	gomega.Expect(cert.DNSNames).To(gomega.ConsistOf(expectedSANs), "Expect cert SAN's to match expected service DNS names")
}

func MakeTestCA(signer string) *crypto.CA {
	caConfig, err := crypto.MakeSelfSignedCAConfigForDuration(
		signer,
		100*365*24*time.Hour, // 100years*365days*24hours
	)
	gomega.Expect(err).To(gomega.BeNil(), "Error creating CA config")
	return &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          caConfig,
	}
}

func CreateNode(c kubernetes.Interface, name string, labels map[string]string, annotations map[string]string) *corev1.Node {
	node := &corev1.Node{
		TypeMeta: metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if labels != nil {
		node.Labels = labels
	}
	if annotations != nil {
		node.Annotations = annotations
	}

	node, err := c.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return node
}

func CreateWindowsNode(cs kubernetes.Interface, name string, variant operator.ProductVariant, version string) *corev1.Node {
	return CreateNode(cs, name,
		map[string]string{"kubernetes.io/os": "windows"},
		map[string]string{})
}

func AssertNodesUnchanged(c kubernetes.Interface, nodes ...*corev1.Node) error {
	for _, node := range nodes {
		newNode, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
		gomega.Expect(err).To(gomega.BeNil())
		if !reflect.DeepEqual(node, newNode) {
			return fmt.Errorf("expected node %q to be unchanged", node.Name)
		}
	}
	return nil
}

// DeleteCalicoSystemTierAndExpectWait deletes the tier resource and expects the Reconciler issues a degraded status, waiting for
// the tier to become available before progressing its status further. Assumes that mockStatus has any required initial status
// progression expectations set, and that the Reconciler utilizes the mockStatus object. Assumes the tier resource has been created.
func DeleteCalicoSystemTierAndExpectWait(ctx context.Context, c client.Client, r reconcile.Reconciler, mockStatus *status.MockStatus) {
	err := c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	mockStatus.On("SetDegraded", operator.ResourceNotReady, "Waiting for calico-system tier to be created, see the 'tiers' TigeraStatus for more information", "tiers.projectcalico.org \"calico-system\" not found", mock.Anything).Return()
	_, err = r.Reconcile(ctx, reconcile.Request{})
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	mockStatus.AssertExpectations(ginkgo.GinkgoT())
}

// ExpectWaitForTierWatch expects the Reconciler issues a degraded status, waiting for a Tier watch to be established.
// Assumes that mockStatus has any required initial status progression expectations set, and that the Reconciler utilizes
// the mockStatus object.
func ExpectWaitForTierWatch(ctx context.Context, r reconcile.Reconciler, mockStatus *status.MockStatus) {
	ExpectWaitForWatch(ctx, r, mockStatus, "Waiting for Tier watch to be established")
}

// ExpectWaitForWatch expects the Reconciler issues a degraded status, waiting for a watch to be established.
// Assumes that mockStatus has any required initial status progression expectations set, and that the Reconciler utilizes
// the mockStatus object.
func ExpectWaitForWatch(ctx context.Context, r reconcile.Reconciler, mockStatus *status.MockStatus, message string) {
	mockStatus.On("SetDegraded", operator.ResourceNotReady, message, mock.Anything, mock.Anything).Return()
	_, err := r.Reconcile(ctx, reconcile.Request{})
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	mockStatus.AssertExpectations(ginkgo.GinkgoT())
}

type ObjectTrackerCall string

const (
	ObjectTrackerCallGet    ObjectTrackerCall = "get"
	ObjectTrackerCallCreate ObjectTrackerCall = "create"
	ObjectTrackerCallUpdate ObjectTrackerCall = "update"
	ObjectTrackerCallList   ObjectTrackerCall = "list"
	ObjectTrackerCallDelete ObjectTrackerCall = "delete"
	ObjectTrackerCallWatch  ObjectTrackerCall = "watch"
)

func NewObjectTrackerWithCalls(clientScheme testing.ObjectScheme) ObjectTrackerWithCalls {
	return ObjectTrackerWithCalls{
		ObjectTracker: testing.NewObjectTracker(clientScheme, scheme.Codecs.UniversalDecoder()),
		callsByGVR:    make(map[schema.GroupVersionResource]map[ObjectTrackerCall]int),
	}
}

// ObjectTrackerWithCalls wraps the default implementation of testing.ObjectTracker to track the calls made.
type ObjectTrackerWithCalls struct {
	testing.ObjectTracker
	callsByGVR map[schema.GroupVersionResource]map[ObjectTrackerCall]int
}

func (o *ObjectTrackerWithCalls) Add(obj runtime.Object) error {
	return o.ObjectTracker.Add(obj)
}

func (o *ObjectTrackerWithCalls) inc(gvr schema.GroupVersionResource, call ObjectTrackerCall) {
	if o.callsByGVR == nil {
		o.callsByGVR = make(map[schema.GroupVersionResource]map[ObjectTrackerCall]int)
	}

	if o.callsByGVR[gvr] == nil {
		o.callsByGVR[gvr] = make(map[ObjectTrackerCall]int)
	}

	o.callsByGVR[gvr][call]++
}

func (o *ObjectTrackerWithCalls) CallCount(gvr schema.GroupVersionResource, call ObjectTrackerCall) int {
	return o.callsByGVR[gvr][call]
}

func (o *ObjectTrackerWithCalls) Get(gvr schema.GroupVersionResource, ns, name string, _ ...metav1.GetOptions) (runtime.Object, error) {
	o.inc(gvr, ObjectTrackerCallGet)
	return o.ObjectTracker.Get(gvr, ns, name)
}

func (o *ObjectTrackerWithCalls) Create(gvr schema.GroupVersionResource, obj runtime.Object, ns string, _ ...metav1.CreateOptions) error {
	o.inc(gvr, ObjectTrackerCallCreate)
	return o.ObjectTracker.Create(gvr, obj, ns)
}

func (o *ObjectTrackerWithCalls) Update(gvr schema.GroupVersionResource, obj runtime.Object, ns string, _ ...metav1.UpdateOptions) error {
	o.inc(gvr, ObjectTrackerCallUpdate)
	return o.ObjectTracker.Update(gvr, obj, ns)
}

func (o *ObjectTrackerWithCalls) List(gvr schema.GroupVersionResource, gvk schema.GroupVersionKind, ns string, _ ...metav1.ListOptions) (runtime.Object, error) {
	o.inc(gvr, ObjectTrackerCallList)
	return o.ObjectTracker.List(gvr, gvk, ns)
}

func (o *ObjectTrackerWithCalls) Delete(gvr schema.GroupVersionResource, ns, name string, _ ...metav1.DeleteOptions) error {
	o.inc(gvr, ObjectTrackerCallDelete)
	return o.ObjectTracker.Delete(gvr, ns, name)
}

func (o *ObjectTrackerWithCalls) Watch(gvr schema.GroupVersionResource, ns string, _ ...metav1.ListOptions) (watch.Interface, error) {
	o.inc(gvr, ObjectTrackerCallWatch)
	return o.ObjectTracker.Watch(gvr, ns)
}

type ProxyTestCase struct {
	Lowercase  bool
	Target     string
	PodProxies []*ProxyConfig
}

type ProxyConfig struct {
	HTTPProxy  string
	HTTPSProxy string
	NoProxy    string
}

func PrettyFormatProxyTestCase(testCase ProxyTestCase) string {
	var containerProxies []string
	for _, containerProxy := range testCase.PodProxies {
		if containerProxy == nil {
			containerProxies = append(containerProxies, "nil")
		} else {
			containerProxies = append(containerProxies, fmt.Sprintf("{HTTPProxy: %s, HTTPSProxy: %s, NoProxy: %s}", containerProxy.HTTPProxy, containerProxy.HTTPSProxy, containerProxy.NoProxy))
		}
	}

	return fmt.Sprintf("Lowercase: %v, Target: %s, containerProxies: [%s]", testCase.Lowercase, testCase.Target, strings.Join(containerProxies, ","))
}
