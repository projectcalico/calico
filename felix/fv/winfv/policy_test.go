// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os/exec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

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
		return "", "", err
	}

	return stdout.String(), stderr.String(), err
}

func getPodIP(name, namespace string) string {
	cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config get pod %s -n %s -o jsonpath='{.status.podIP}'`,
		name, namespace)
	ip, _, err := powershell(cmd)
	if err != nil {
		Fail(fmt.Sprintf("could not get pod IP for %v/%v: %v", namespace, name, err))
	}
	return ip
}

func kubectlExec(command string) error {
	cmd := fmt.Sprintf(`c:\k\kubectl.exe --kubeconfig=c:\k\config -n demo exec %v`, command)
	stdout, stderr, err := powershell(cmd)
	if err != nil {
		log.WithFields(log.Fields{"stderr": stderr, "stdout": stdout}).WithError(err).Error("Error running kubectl command")
		return err
	}
	log.WithFields(log.Fields{"stderr": stderr, "stdout": stdout}).Info("kubectl command succeeded")
	return nil
}

func newClient() clientv3.Interface {
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = apiconfig.Kubernetes
	cfg.Spec.Kubeconfig = `c:\k\config`
	client, err := clientv3.New(*cfg)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return client
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
	var (
		porter, client, clientB, nginx, nginxB string
	)

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
			err := kubectlExec(fmt.Sprintf(`-t client -- wget %v -T 5 -qO -`, porter))
			Expect(err).NotTo(HaveOccurred())
		})
		It("client-b pod can't connect to porter pod", func() {
			err := kubectlExec(fmt.Sprintf(`-t client-b -- wget %v -T 5 -qO -`, porter))
			Expect(err).To(HaveOccurred())
		})
	})
	Context("egress policy tests", func() {
		It("porter pod can connect to nginx pod", func() {
			err := kubectlExec(fmt.Sprintf(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 %v'`, nginx))
			Expect(err).NotTo(HaveOccurred())
		})
		It("porter pod cannot connect to nginx-b pod", func() {
			err := kubectlExec(fmt.Sprintf(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 %v'`, nginxB))
			Expect(err).To(HaveOccurred())
		})
		It("porter pod cannot connect to google.com", func() {
			err := kubectlExec(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 www.google.com'`)
			Expect(err).To(HaveOccurred())
		})
		It("porter pod can connect to nginxB after creating service egress policy", func() {
			// Assert nginx-b is not reachable.
			err := kubectlExec(fmt.Sprintf(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 %v'`, nginxB))
			Expect(err).To(HaveOccurred())

			// Create a policy allowing to the nginx-b service.
			client := newClient()
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

			// Assert that it's now reachable.
			err = kubectlExec(fmt.Sprintf(`-t porter -- powershell -Command 'Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 %v'`, nginxB))
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
