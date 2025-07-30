/*
Copyright (c) 2018 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This package makes public methods out of some of the utility methods for testing windows cluster found at test/e2e/network_policy.go
// Eventually these utilities should replace those and be used for any calico tests

package windows

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/e2e/pkg/utils"

	"github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
)

// Map to store serviceName and respective endpointIP
var ServiceEndpointIP = map[string]string{}

// Check if we are running windows specific test cases.
func RunningWindowsTest() bool {
	cfg, _ := ginkgo.GinkgoConfiguration()
	for _, s := range cfg.FocusStrings {
		if strings.Contains(s, "RunsOnWindows") {
			return true
		}
	}
	return false
}

// For Windows on OpenShift, pods scheduled for non-default namespaces must
// disable SCC. See: https://bugzilla.redhat.com/show_bug.cgi?id=1768858
//
// TODO(lmm): Once we have moved away from using Windows Machine Config
// Bootstrapper to provision OCP Windows nodes, we should delete this.
func MaybeUpdateNamespaceForOpenShift(f *framework.Framework, nsName string) {
	if utils.IsOpenShift(f) && RunningWindowsTest() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ns, err := f.ClientSet.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
		if err != nil {
			err = fmt.Errorf("could not get namespace for Windows test on OpenShift: %w", err)
		}
		Expect(err).ToNot(HaveOccurred())

		logrus.Info("Running Windows test on OpenShift, checking if namespace label 'openshift.io/run-level: 1'...")
		// Check if we need to update the ns or not
		if v, ok := ns.Labels["openshift.io/run-level"]; !ok || v != "1" {
			ns.Labels["openshift.io/run-level"] = "1"
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, err := f.ClientSet.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
			if err != nil {
				err = fmt.Errorf("could not update namespace for Windows test on OpenShift: %w", err)
			}
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("Labels on namespace %q updated", ns.Name)
		}
	}
}

// Temporarily disable readiness check for windows cluster if flag is set.
func DisableReadiness() bool {
	return os.Getenv("WINDOWS_DISABLE_READINESS") == "true"
}

// This is a hack for windows to use EndpointIP instead of service's
// ClusterIP, Since we have known issue with service's ClusterIP
func GetTarget(f *framework.Framework, service *v1.Service, targetPort int) (string, string) {
	var targetIP string
	// check if serviceEndpointIP is already present in map,else
	// raise a request to get it
	key := fmt.Sprintf("%s-%s", service.Namespace, service.Name)
	if ip, exist := ServiceEndpointIP[key]; exist {
		targetIP = ip
	} else {
		targetIP = getServiceEndpointIP(f, service.Namespace, service.Name)
		ServiceEndpointIP[key] = targetIP
	}
	serviceTarget := fmt.Sprintf("http://%s:%d", service.Spec.ClusterIP, targetPort)
	podTarget := fmt.Sprintf("http://%s:%d", targetIP, targetPort)
	fmt.Printf("podTarget :%s and serviceTarget :%s \n", podTarget, serviceTarget)
	return podTarget, serviceTarget
}

// Since we have a known issue related to service ClusterIP on windows,hence using EndpointIP
// to connect
func getServiceEndpointIP(f *framework.Framework, svcNSName string, svcName string) string {
	var err error
	err = framework.WaitForServiceEndpointsNum(context.Background(), f.ClientSet, svcNSName, svcName, 1, time.Second, 60*time.Second)
	if err != nil {
		framework.Failf("Unable to get endpoint for service %s: %v", svcName, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint, err := f.ClientSet.CoreV1().Endpoints(svcNSName).Get(ctx, svcName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	Expect(endpoint.Subsets).To(HaveLen(1), fmt.Sprintf("Failed to find endpoint subset for service %s", svcName))
	Expect(endpoint.Subsets[0].Addresses).To(HaveLen(1), fmt.Sprintf("Failed to find endpoint address for service %s", svcName))
	endpointIP := endpoint.Subsets[0].Addresses[0].IP
	logrus.Infof("ServiceName: %s endpointIP: %s.", svcName, endpointIP)
	return endpointIP
}

// function to cleanup ServiceName and EndpointIP map
func CleanupServiceEndpointMap() {
	for i := range ServiceEndpointIP {
		delete(ServiceEndpointIP, i)
	}
}
