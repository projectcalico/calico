// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package flannelmigration_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	gocidr "github.com/apparentlymart/go-cidr/cidr"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	backend "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	// Flannel migration controller will run on this node.
	controllerNodeName = "node-0"
	// Master node Name.
	masterNodeName = "node-1"

	flannelDs = "kube-flannel-ds-amd64"

	flannelSubnetEnv = "FLANNEL_NETWORK=192.168.0.0/16;FLANNEL_SUBNET=192.168.1.1/24;FLANNEL_MTU=8951;FLANNEL_IPMASQ=true;"
)

var emptyLabel = map[string]string{}

var _ = Describe("flannel-migration-controller FV test", func() {
	var (
		etcd                *containers.Container
		migrationController *containers.Container
		apiserver           *containers.Container
		calicoClient        client.Interface
		bc                  backend.Client
		k8sClient           *kubernetes.Clientset
		controllerManager   *containers.Container
		kconfigfile         *os.File
		err                 error
		flannelCluster      *testutils.FlannelCluster
	)

	logKubectl := func(args ...string) {
		out, err := apiserver.ExecOutput(args...)
		Expect(err).ShouldNot(HaveOccurred())
		logrus.Infof("--- kubectl output --- \n%s", out)
	}

	startController := func() {
		// Add 3 seconds delay before main thread starts, this is to make sure FV can add watch channels
		// before controller logs out to stderr.
		// (container.Run returns after 'docker ps' shows the container, the polling interval is 1 second.)
		// Add 60 seconds delay before main thread exits, this is to make sure controller is still running
		// after test case completed and stopped by AfterEach.
		migrationController = testutils.RunFlannelMigrationController(kconfigfile.Name(), controllerNodeName, flannelSubnetEnv, 3, 60)
	}

	stopController := func() {
		migrationController.Stop()
	}

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kconfigfile, err = ioutil.TempFile("", "ginkgo-migrationcontroller")
		Expect(err).NotTo(HaveOccurred())

		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigfile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigfile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		k8sClient, err = testutils.GetK8sClient(kconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Apply the necessary CRDs. There can sometimes be a delay between starting
		// the API server and when CRDs are apply-able, so retry here.
		apply := func() error {
			out, err := apiserver.ExecOutput("kubectl", "apply", "-f", "/crds/")
			if err != nil {
				return fmt.Errorf("%s: %s", err, out)
			}
			return nil
		}
		Eventually(apply, 10*time.Second).ShouldNot(HaveOccurred())

		// Make a Calico client and backend client.
		type accessor interface {
			Backend() backend.Client
		}
		calicoClient = testutils.GetCalicoClient(apiconfig.Kubernetes, "", kconfigfile.Name())
		bc = calicoClient.(accessor).Backend()

		// Run controller manager.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)

		// Initialise a new Flannel cluster
		flannelCluster = testutils.NewFlannelCluster(k8sClient, "192.168.0.0/16")

		// Setup cluster
		flannelCluster.AddFlannelDaemonset(flannelDs)
		flannelCluster.AddCalicoDaemonset("calico-node")
		flannelCluster.AddDefaultCalicoConfigMap()

		// Add master and controller nodes.
		flannelCluster.AddFlannelNode(controllerNodeName, "192.168.1.0/24", "vxlan", "8e:74:9a:30:24:01", "172.16.0.1", emptyLabel, false)
		flannelCluster.AddFlannelNode(masterNodeName, "192.168.2.0/24", "vxlan", "8e:74:9a:30:24:02", "172.16.0.2", emptyLabel, true)
		flannelCluster.AddFlannelNode("node-2", "192.168.3.0/24", "vxlan", "8e:74:9a:30:24:03", "172.16.0.3", emptyLabel, false)
	})

	AfterEach(func() {
		flannelCluster.Reset()
		os.Remove(kconfigfile.Name())
		controllerManager.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	Context("Basic FV tests", func() {
		BeforeEach(func() {
			startController()
		})
		AfterEach(func() {
			stopController()
		})

		It("should initialize the datastore at start-of-day", func() {
			var info *api.ClusterInformation
			Eventually(func() *api.ClusterInformation {
				info, _ = calicoClient.ClusterInformation().Get(context.Background(), "default", options.GetOptions{})
				return info
			}, 10*time.Second).ShouldNot(BeNil())

			Expect(info.Spec.ClusterGUID).To(MatchRegexp("^[a-f0-9]{32}$"))
			Expect(info.Spec.ClusterType).To(Equal("k8s,kdd"))
			Expect(*info.Spec.DatastoreReady).To(BeTrue())
		})

		Context("Healthcheck FV tests", func() {
			It("should pass health check", func() {
				By("Waiting for an initial readiness report")
				Eventually(func() []byte {
					cmd := exec.Command("docker", "exec", migrationController.Name, "/usr/bin/check-status", "-r")
					stdoutStderr, _ := cmd.CombinedOutput()

					return stdoutStderr
				}, 20*time.Second, 500*time.Millisecond).ShouldNot(ContainSubstring("initialized to false"))

				By("Waiting for the controller to be ready")
				Eventually(func() string {
					cmd := exec.Command("docker", "exec", migrationController.Name, "/usr/bin/check-status", "-r")
					stdoutStderr, _ := cmd.CombinedOutput()

					return strings.TrimSpace(string(stdoutStderr))
				}, 20*time.Second, 500*time.Millisecond).Should(Equal("Ready"))
			})
		})
	})

	Context("Should migrate FV tests", func() {
		AfterEach(func() {
			migrationController.Stop()
		})

		It("Should report nothing to do if Flannel daemonset not exists", func() {
			// remove flannel daemonset
			_, err := apiserver.ExecOutput("kubectl", "delete", "daemonset", flannelDs, "-n", "kube-system")
			Expect(err).ShouldNot(HaveOccurred())

			startController()

			w := migrationController.WatchStderrFor(regexp.MustCompile(`.*no migration process is needed.*`))
			Eventually(w, "10s").Should(BeClosed(),
				"Timed out waiting for migration controller report 'no migration process is needed'")
		})

		It("Should report error if Flannel daemonset has addon manager label", func() {
			// add addon manager label
			_, err := apiserver.ExecOutput("kubectl", "label", "daemonset", flannelDs, "-n", "kube-system", "addonmanager.kubernetes.io/mode=EnsureExists")
			Expect(err).ShouldNot(HaveOccurred())

			startController()

			w := migrationController.WatchStderrFor(regexp.MustCompile(`.*abort migration process.*`))
			Eventually(w, "10s").Should(BeClosed(),
				"Timed out waiting for migration controller report 'abort migration process'")
		})
	})

	Context("IPAM migrate FV tests", func() {
		checkCalicoIPAM := func() {
			// Wait for ipam migration is done.
			w := migrationController.WatchStderrFor(regexp.MustCompile(`.*nodes completed IPAM migration process.*`))
			Eventually(w, "10s").Should(BeClosed(),
				"Timed out waiting for migration controller report 'nodes completed IPAM migration process'")

			Expect(len(flannelCluster.FlannelNodes)).To(Equal(3))
			// Check Calico IPAM.
			validateCalicoIPAM(flannelCluster, calicoClient, bc)
		}

		AfterEach(func() {
			stopController()
		})

		It("Should create ippool, felixconfiguration and block affinities", func() {
			startController()
			checkCalicoIPAM()
		})

		It("Should support controller restart after IPAM is done", func() {
			startController()
			checkCalicoIPAM()

			stopController()

			startController()
			checkCalicoIPAM()
		})

		It("Should support Canal with a default ippool and vxlan disabled", func() {
			p := api.NewIPPool()
			p.Name = "default-ipv4-ippool"
			p.Spec.CIDR = "192.168.0.0/16"
			p.Spec.BlockSize = 26
			p.Spec.NodeSelector = "all()"
			p.Spec.Disabled = false
			_, err := calicoClient.IPPools().Create(context.Background(), p, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Remove flannel daemonset, add Canal daemonet.
			_, err = apiserver.ExecOutput("kubectl", "delete", "daemonset", flannelDs, "-n", "kube-system")
			Expect(err).ShouldNot(HaveOccurred())
			flannelCluster.AddCanalDaemonset("canal")

			startController()
			checkCalicoIPAM()
		})
	})

	Context("Node ordering FV tests", func() {
		checkNodeOrdering := func() {
			// Set watch for node index.
			w0 := migrationController.WatchStderrFor(regexp.MustCompile(`.*node-2\[index 0\].*`))
			w1 := migrationController.WatchStderrFor(regexp.MustCompile(`.*node-3\[index 1\].*`))
			w2 := migrationController.WatchStderrFor(regexp.MustCompile(`.*node-1\[index 2\].*`))
			w3 := migrationController.WatchStderrFor(regexp.MustCompile(`.*node-0\[index 3\].*`))

			// Wait for ipam migration is done.
			w := migrationController.WatchStderrFor(regexp.MustCompile(`.*nodes completed IPAM migration process.*`))
			Eventually(w, "10s").Should(BeClosed(),
				"Timed out waiting for migration controller report 'nodes completed IPAM migration process'")

			Expect(w0).Should(BeClosed())
			Expect(w1).Should(BeClosed())
			Expect(w2).Should(BeClosed())
			Expect(w3).Should(BeClosed())
		}

		BeforeEach(func() {
			flannelCluster.AddFlannelNode("node-3", "192.168.4.0/24", "vxlan", "8e:74:9a:30:24:04", "172.16.0.4", emptyLabel, false)
			logKubectl("kubectl", "get", "node")
		})

		AfterEach(func() {
			stopController()
		})

		It("Should proceed with correct order", func() {
			startController()
			checkNodeOrdering()
		})

		It("Should always proceed with correct order", func() {
			startController()
			checkNodeOrdering()

			stopController()

			startController()
			checkNodeOrdering()
		})
	})
})

// Given a Flannel cluster, validate if Calico IPAM has corresponding setup.
func validateCalicoIPAM(fc *testutils.FlannelCluster, client client.Interface, bc backend.Client) {
	ctx := context.Background()

	// Check ippool.
	defaultPool, err := client.IPPools().Get(ctx, "default-ipv4-ippool", options.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred())
	Expect(defaultPool.Spec.CIDR).To(Equal(fc.Network))
	Expect(defaultPool.Spec.BlockSize).To(Equal(26))
	Expect(defaultPool.Spec.NATOutgoing).To(Equal(true))
	Expect(defaultPool.Spec.VXLANMode).To(Equal(api.VXLANMode(api.VXLANModeAlways)))

	// Check felix configuration.
	defaultConfig, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
	Expect(err).ShouldNot(HaveOccurred())
	Expect(*defaultConfig.Spec.VXLANVNI).To(Equal(1))
	Expect(*defaultConfig.Spec.VXLANPort).To(Equal(8472))
	Expect(*defaultConfig.Spec.VXLANMTU).To(Equal(8951))

	// Check each node.
	for nodeName, fn := range fc.FlannelNodes {
		// Get first IP address which is used by Flannel as vtep IP.
		ip, nodeCidr, err := net.ParseCIDR(fn.PodCidr)
		vtepIP := cnet.IP{IP: ip}
		Expect(err).ShouldNot(HaveOccurred())

		// Check Calico node spec.
		node, err := client.Nodes().Get(ctx, nodeName, options.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(node.Spec.BGP).NotTo(Equal(nil))

		Expect(node.Spec.BGP.IPv4Address).To(Equal(fn.PublicIP + "/32"))
		Expect(node.Spec.IPv4VXLANTunnelAddr).To(Equal(vtepIP.String()))
		Expect(node.Spec.VXLANTunnelMACAddr).To(Equal(fn.VtepMac))

		// Check tunnel ip been correctly assigned.
		attr, _, err := client.IPAM().GetAssignmentAttributes(ctx, vtepIP)
		Expect(err).NotTo(HaveOccurred())
		Expect(attr[ipam.AttributeNode]).To(Equal(nodeName))
		Expect(attr[ipam.AttributeType]).To(Equal(ipam.AttributeTypeVXLAN))

		// Check block affinities been correctly claimed.
		opts := model.BlockAffinityListOptions{Host: nodeName, IPVersion: 4}
		datastoreObjs, err := bc.List(context.Background(), opts, "")
		Expect(err).ShouldNot(HaveOccurred())
		// Iterate through and extract the block CIDRs.
		var blocks []*net.IPNet
		for _, o := range datastoreObjs.KVPairs {
			k := o.Key.(model.BlockAffinityKey)
			cidr := net.IPNet{IP: k.CIDR.IP, Mask: k.CIDR.Mask}
			blocks = append(blocks, &cidr)
		}
		Expect(len(blocks)).To(Equal(4))
		err = gocidr.VerifyNoOverlap(blocks, nodeCidr)
		Expect(err).ShouldNot(HaveOccurred())
	}
}
