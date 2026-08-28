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
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/tigera/operator/pkg/active"
	"github.com/tigera/operator/pkg/common"
	"k8s.io/client-go/kubernetes"
)

var _ = Describe("pkg/active with apiserver", func() {
	var (
		c                client.Client
		cs               *kubernetes.Clientset
		osExited         bool
		originalTickRate time.Duration
		log              logr.Logger
	)
	BeforeEach(func() {
		c, cs = setup()
		log = logf.Log.WithName("active-test-logger")
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
			Spec:       corev1.NamespaceSpec{},
		}
		err := c.Create(context.Background(), ns)
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
		osExited = false
		active.OsExitOverride = func(_ int) {
			osExited = true
		}
		originalTickRate = active.TickerRateOverride
		active.TickerRateOverride = 5 * time.Millisecond
	})

	AfterEach(func() {
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
			Spec:       corev1.NamespaceSpec{},
		}
		err := c.Delete(context.Background(), ns)
		Expect(err).NotTo(HaveOccurred())
		ExpectResourceDestroyed(c, ns, 10*time.Second)
		active.OsExitOverride = os.Exit
		active.TickerRateOverride = originalTickRate
	})

	It("WaitUntilActive doesn't wait if no active ConfigMap exists", func() {
		By("Starting no ConfigMap")
		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()
		finished := false
		go func() {
			active.WaitUntilActive(cs, c, ctx, log)
			finished = true
		}()

		Eventually(func() error {
			if !finished {
				return fmt.Errorf("WaitUntilActive did not finish in alloted time")
			}
			return nil
		}, 5*time.Second).Should(BeNil())

		Expect(osExited).To(BeFalse(), "WaitUntilActive called os.Exit unexpectedly")
	})

	It("WaitUntilActive waits until ConfigMap specifies namespace as active", func() {
		By("Starting with ConfigMap")
		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()

		Expect(c.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      active.ActiveConfigMapName,
				Namespace: common.CalicoNamespace,
			},
			Data: map[string]string{"active-namespace": "active-test-namespace"},
		})).ShouldNot(HaveOccurred())
		finished := false
		go func() {
			active.WaitUntilActive(cs, c, ctx, log)
			finished = true
		}()

		Consistently(func() error {
			if finished == true {
				return fmt.Errorf("WaitUntilActive finished before expected")
			}
			return nil
		}, 3*time.Second, 50*time.Millisecond).Should(BeNil())

		Expect(c.Update(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      active.ActiveConfigMapName,
				Namespace: common.CalicoNamespace,
			},
			Data: map[string]string{"active-namespace": "tigera-operator"},
		})).ShouldNot(HaveOccurred())

		Eventually(func() error {
			if !finished {
				return fmt.Errorf("WaitUntilActive did not finish in alloted time")
			}
			return nil
		}, 5*time.Second).Should(BeNil())

		Expect(osExited).To(BeFalse(), "WaitUntilActive called os.Exit unexpectedly")
	})
})

func setup() (client.Client, *kubernetes.Clientset) {
	// Create a Kubernetes client.
	cfg, err := config.GetConfig()
	Expect(err).NotTo(HaveOccurred())
	c, err := client.New(cfg, client.Options{})
	Expect(err).NotTo(HaveOccurred())
	cs := kubernetes.NewForConfigOrDie(cfg)

	return c, cs
}
