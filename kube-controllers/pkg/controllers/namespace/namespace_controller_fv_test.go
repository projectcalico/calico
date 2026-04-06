// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
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

package namespace_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/namespace"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var (
	testEnv      *testutils.TestEnv
	calicoClient client.Interface
)

func init() {
	logrus.SetFormatter(&logutils.Formatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

func TestMain(m *testing.M) {
	var err error
	testEnv, err = testutils.NewTestEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest setup: %v\n", err)
		os.Exit(1)
	}

	calicoClient, err = testEnv.NewCalicoEtcdClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "calico client setup: %v\n", err)
		testEnv.Stop()
		os.Exit(1)
	}

	code := m.Run()
	calicoClient.Close()
	if err := testEnv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "envtest teardown: %v\n", err)
	}
	os.Exit(code)
}

// startNamespaceController creates and starts the namespace controller.
// The controller is stopped when the test ends.
func startNamespaceController(t *testing.T, ctx context.Context) {
	t.Helper()
	cfg := config.GenericControllerConfig{
		ReconcilerPeriod: 2 * time.Second,
		NumberOfWorkers:  1,
	}
	ctrl := namespace.NewNamespaceController(ctx, testEnv.K8sClient, calicoClient, cfg)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go ctrl.Run(stop)
}

// TestFV_NamespaceProfileCreated verifies that the namespace controller creates
// a Profile in the Calico datastore when a new Namespace is created.
func TestFV_NamespaceProfileCreated(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	startNamespaceController(t, ctx)

	nsName := "test-ns-create"
	profName := "kns." + nsName
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"peanut": "butter",
			},
		},
	}
	_, err := testEnv.K8sClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	t.Cleanup(func() {
		if err := testEnv.K8sClient.CoreV1().Namespaces().Delete(ctx, nsName, metav1.DeleteOptions{}); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	g.Eventually(func() error {
		_, err := calicoClient.Profiles().Get(ctx, profName, options.GetOptions{})
		return err
	}, 15*time.Second, 500*time.Millisecond).Should(Succeed())
}

// TestFV_NamespaceProfileRecreated verifies that deleting a Profile causes the
// controller to recreate it.
func TestFV_NamespaceProfileRecreated(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	startNamespaceController(t, ctx)

	nsName := "test-ns-recreate"
	profName := "kns." + nsName
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"peanut": "butter",
			},
		},
	}
	_, err := testEnv.K8sClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	t.Cleanup(func() {
		if err := testEnv.K8sClient.CoreV1().Namespaces().Delete(ctx, nsName, metav1.DeleteOptions{}); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	// Wait for the profile to be created.
	g.Eventually(func() error {
		_, err := calicoClient.Profiles().Get(ctx, profName, options.GetOptions{})
		return err
	}, 15*time.Second, 500*time.Millisecond).Should(Succeed())

	// Delete the profile and verify the controller recreates it.
	_, err = calicoClient.Profiles().Delete(ctx, profName, options.DeleteOptions{})
	g.Expect(err).NotTo(HaveOccurred())

	g.Eventually(func() error {
		_, err := calicoClient.Profiles().Get(ctx, profName, options.GetOptions{})
		return err
	}, 15*time.Second, 500*time.Millisecond).Should(Succeed())
}

// TestFV_NamespaceProfileLabelsUpdated verifies that the controller restores
// the correct labels on a Profile when they are manually cleared.
func TestFV_NamespaceProfileLabelsUpdated(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	startNamespaceController(t, ctx)

	nsName := "test-ns-labels"
	profName := "kns." + nsName
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"peanut": "butter",
			},
		},
	}
	_, err := testEnv.K8sClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	t.Cleanup(func() {
		if err := testEnv.K8sClient.CoreV1().Namespaces().Delete(ctx, nsName, metav1.DeleteOptions{}); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	// Wait for the profile to be created.
	g.Eventually(func() error {
		_, err := calicoClient.Profiles().Get(ctx, profName, options.GetOptions{})
		return err
	}, 15*time.Second, 500*time.Millisecond).Should(Succeed())

	// Clear the labels and verify the controller restores them.
	profile, err := calicoClient.Profiles().Get(ctx, profName, options.GetOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	profile.Spec.LabelsToApply = map[string]string{}
	_, err = calicoClient.Profiles().Update(ctx, profile, options.SetOptions{})
	g.Expect(err).NotTo(HaveOccurred())

	g.Eventually(func() map[string]string {
		prof, _ := calicoClient.Profiles().Get(ctx, profName, options.GetOptions{})
		if prof == nil {
			return nil
		}
		return prof.Spec.LabelsToApply
	}, 15*time.Second, 500*time.Millisecond).ShouldNot(BeEmpty())
}
