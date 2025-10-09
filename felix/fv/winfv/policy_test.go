// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.
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

package winfv_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func Powershell(args ...string) string {
	stdOut, stdErr, err := powershell(args...)
	if err != nil {
		log.Infof("Test Fail -- Powershell() error: %s, stdOut: %s, stdErr: %s,", err, stdOut, stdErr)
		PauseForDebug()
	}
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return stdOut
}

func PowershellWithError(args ...string) string {
	stdOut, stdErr, err := powershell(args...)
	log.Infof("PowershellWithError() error: %s, stdOut: %s, stdErr: %s,", err, stdOut, stdErr)
	if err == nil {
		log.Info("Test Fail -- PowershellWithError() did not return an error as expected")
		PauseForDebug()
	}
	ExpectWithOffset(1, err).To(HaveOccurred())
	return stdErr
}

func powershell(args ...string) (string, string, error) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", "", err
	}

	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(ps, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	return stdout.String(), stderr.String(), err
}

// PauseForDebug checks for the existence of a "pause-for-debug" namespace and waits
// in a loop if it exists, allowing developers to pause test execution for debugging.
// The function checks every 30 seconds and will timeout after 1 hour.
// To use: create the namespace with `kubectl create ns pause-for-debug`
// To resume: delete the namespace with `kubectl delete ns pause-for-debug`
func PauseForDebug() {
	maxWaitTime := 1 * time.Hour
	startTime := time.Now()

	for {
		cmd := `c:\k\kubectl.exe --kubeconfig=c:\k\config get ns pause-for-debug`
		_, stdErr, err := powershell(cmd)
		if err != nil {
			log.Infof("PauseForDebug: namespace 'pause-for-debug' does not exist, continuing with tests. Error: %s, stdErr: %s", err, stdErr)
			return
		}

		elapsed := time.Since(startTime)
		if elapsed >= maxWaitTime {
			log.Infof("PauseForDebug: timeout reached after 1 hour, continuing with tests even though namespace 'pause-for-debug' still exists")
			return
		}

		log.Infof("PauseForDebug: namespace 'pause-for-debug' exists, waiting 30 seconds before checking again. Elapsed time: %v", elapsed)
		time.Sleep(30 * time.Second)
	}
}

func getPodIP(name, namespace string) string {
	cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config get pod %s -n %s -o jsonpath='{.status.podIP}'`,
		name, namespace)
	return Powershell(cmd)
}

func kubectlExec(command string) {
	cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config -n demo exec %v`, command)
	_ = Powershell(cmd)
}

func kubectlExecWithErrors(command string) {
	cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config -n demo exec %v`, command)
	err := PowershellWithError(cmd)
	log.Infof("Error: %s", err)
}

func newClient() clientv3.Interface {
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = apiconfig.Kubernetes
	cfg.Spec.Kubeconfig = `c:\k\config`
	cfg.Spec.CalicoAPIGroup = os.Getenv("CALICO_API_GROUP")
	client, err := clientv3.New(*cfg)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	mustInitDatastore(client)
	return client
}

func mustInitDatastore(client clientv3.Interface) {
	Eventually(func() error {
		log.Info("Initializing the datastore...")
		ctx, cancelFun := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFun()
		err := client.EnsureInitialized(
			ctx,
			"v3.0.0-test",
			"felix-fv",
		)
		log.WithError(err).Info("EnsureInitialized result")
		return err
	}).ShouldNot(HaveOccurred(), "mustInitDatastore failed")
}

// These Windows policy FV tests rely on a 2 node cluster (1 Linux and 1 Windows) provisioned using internal tooling.
// The test infra setup creates some pods:
// - "client" and "clientB" are busybox pods
// - "nginx" and "nginxB" are nginx pods
// - "porter" is a Windows server/client pod using the calico/porter image
//
// The test infra setup also applies some network policies on the pods:
// - "allow-dns": egress policy that allows the porter pod to reach UDP port 53
// - "allow-nginx": egress policy that allows the porter pod to reach the nginx pods on TCP port 80
// - "allow-client": ingress policy that allows the client pods to reach the porter pods on TCP port 80
var _ = Describe("Windows policy test", func() {
	var porter, client, clientB, nginx, nginxB string

	BeforeEach(func() {
		// Get IPs of the pods installed by the test infra setup.
		client = getPodIP("client", "demo")
		clientB = getPodIP("client-b", "demo")
		porter = getPodIP("porter", "demo")
		nginx = getPodIP("nginx", "demo")
		nginxB = getPodIP("nginx-b", "demo")
		log.Infof("Pod IPs: client %s, client-b %s, porter %s, nginx %s, nginx-b %s",
			client, clientB, porter, nginx, nginxB)

		Expect(client).NotTo(BeEmpty())
		Expect(clientB).NotTo(BeEmpty())
		Expect(porter).NotTo(BeEmpty())
		Expect(nginx).NotTo(BeEmpty())
		Expect(nginxB).NotTo(BeEmpty())
	})

	Context("ingress policy tests", func() {
		It("client pod can connect to porter pod", func() {
			kubectlExec(fmt.Sprintf(`-t client -- wget %v -T 5 -qO -`, porter))
		})
		It("client-b pod can't connect to porter pod", func() {
			kubectlExecWithErrors(fmt.Sprintf(`-t client-b -- wget %v -T 5 -qO -`, porter))
		})
	})
	Context("egress policy tests", func() {
		It("porter pod can connect to nginx pod", func() {
			kubectlExec(fmt.Sprintf(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 %v'`, nginx))
		})
		It("porter pod cannot connect to nginx-b pod", func() {
			kubectlExecWithErrors(fmt.Sprintf(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 %v'`, nginxB))
		})
		It("porter pod cannot connect to google.com", func() {
			kubectlExecWithErrors(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 www.google.com'`)
		})
		It("porter pod can connect to nginxB after creating service egress policy", func() {
			// Assert nginx-b is not reachable.
			kubectlExecWithErrors(fmt.Sprintf(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 %v'`, nginxB))

			// Create a policy allowing to the nginx-b service.
			client := newClient()

			By("creating tier1 and a network policy in it")
			tier1 := v3.NewTier()
			tier1.Name = "tier1"
			order := float64(10)
			tier1.Spec.Order = &order
			_, err := client.Tiers().Create(context.Background(), tier1, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_, err = client.Tiers().Delete(context.Background(), tier1.Name, options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())
			}()

			p1 := v3.NetworkPolicy{}
			p1.Name = fmt.Sprintf("%v.allow-nginx-x", tier1.Name)
			p1.Namespace = "demo"
			p1.Spec.Tier = tier1.Name
			p1.Spec.Selector = "all()"
			p1.Spec.Egress = []v3.Rule{
				{
					Action: v3.Allow,
					Destination: v3.EntityRule{
						Services: &v3.ServiceMatch{
							Name:      "nginx-x",
							Namespace: "demo",
						},
					},
				},
			}
			_, err = client.NetworkPolicies().Create(context.Background(), &p1, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_, err = client.NetworkPolicies().Delete(context.Background(), "demo", p1.Name, options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())
			}()

			By("creating a network policy to allow traffic")
			p := v3.NetworkPolicy{}
			p.Name = "allow-nginx-b"

			p.Namespace = "demo"
			p.Spec.Selector = "all()"
			p.Spec.Egress = []v3.Rule{
				{
					Action: v3.Allow,
					Destination: v3.EntityRule{
						Services: &v3.ServiceMatch{
							Name:      "nginx-b",
							Namespace: "demo",
						},
					},
				},
			}
			_, err = client.NetworkPolicies().Create(context.Background(), &p, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_, err = client.NetworkPolicies().Delete(context.Background(), "demo", "allow-nginx-b", options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())
			}()

			By("asserting destination is not reachable")
			// Assert nginx-b is not reachable.
			kubectlExecWithErrors(fmt.Sprintf(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 %v'`, nginxB))

			By("updating tier1 default action to pass")
			tier1, err = client.Tiers().Get(context.Background(), tier1.Name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			passAction := v3.Pass
			tier1.Spec.DefaultAction = &passAction
			_, err = client.Tiers().Update(context.Background(), tier1, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("asserting destination is now reachable")
			// Assert that it's now reachable.
			kubectlExec(fmt.Sprintf(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 %v'`, nginxB))
		})
	})
})
