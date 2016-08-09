package main_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"net"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	. "github.com/projectcalico/calico-cni/test_utils"
	"github.com/vishvananda/netlink"
)

// Some ideas for more tests
// Test that both etcd_endpoints and etcd_authity can be used
// Test k8s
// test bad network name
// badly formatted netconf
// vary the MTU
// Existing endpoint

var _ = Describe("CalicoCni", func() {
	hostname, _ := os.Hostname()
	BeforeEach(func() {
		cmd := fmt.Sprintf("etcdctl --endpoints http://%s:2379 rm /calico --recursive | true", os.Getenv("ETCD_IP"))
		session, err := gexec.Start(exec.Command("bash", "-c", cmd), GinkgoWriter, GinkgoWriter)
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(session).Should(gexec.Exit())
	})

	Describe("Run Calico CNI plugin", func() {
		Context("using host-local IPAM", func() {
			netconf := fmt.Sprintf(`
			{
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  }
			}`, os.Getenv("ETCD_IP"))

			It("successfully networks the namespace", func() {
				containerID, netnspath, session, contVeth, contAddresses, contRoutes, err := CreateContainer(netconf)
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				result := types.Result{}
				if err := json.Unmarshal(session.Out.Contents(), &result); err != nil {
					panic(err)
				}
				mac := contVeth.Attrs().HardwareAddr

				ip := result.IP4.IP.IP.String()
				Expect(result.IP4.IP.Mask.String()).Should(Equal("ffffffff"))

				// etcd things:
				// Profile is created with correct details
				Expect(GetEtcdString("/calico/v1/policy/profile/net1/tags")).Should(MatchJSON(`["net1"]`))
				Expect(GetEtcdString("/calico/v1/policy/profile/net1/rules")).Should(MatchJSON(`{"inbound_rules":[{"action":"allow","src_tag":"net1"}],"outbound_rules":[{"action":"allow"}]}`))

				// The endpoint is created in etcd
				endpoint_path := GetEtcdMostRecentSubdir(fmt.Sprintf("/calico/v1/host/%s/workload/cni/%s", hostname, containerID))
				Expect(endpoint_path).Should(ContainSubstring(containerID))
				Expect(GetEtcdString(endpoint_path)).Should(MatchJSON(fmt.Sprintf(`{"state":"active","name":"cali%s","mac":"%s","profile_ids":["net1"],"ipv4_nets":["%s/32"]}`, containerID, mac, ip)))

				// Routes and interface on host - there's is nothing to assert on the routes since felix adds those.
				//fmt.Println(Cmd("ip link show")) // Useful for debugging
				hostVeth, _ := netlink.LinkByName("cali" + containerID)
				Expect(hostVeth.Attrs().Flags.String()).Should(ContainSubstring("up"))
				Expect(hostVeth.Attrs().MTU).Should(Equal(1500))

				// Routes and interface in netns
				Expect(contVeth.Attrs().Flags.String()).Should(ContainSubstring("up"))

				// Assume the first IP is the IPv4 address
				Expect(contAddresses[0].IP.String()).Should(Equal(ip))
				Expect(contRoutes).Should(SatisfyAll(ContainElement(netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Gw:        net.IPv4(169, 254, 1, 1).To4(),
				}),
					ContainElement(netlink.Route{
						LinkIndex: contVeth.Attrs().Index,
						Scope:     netlink.SCOPE_LINK,
						Dst:       &net.IPNet{IP: net.IPv4(169, 254, 1, 1).To4(), Mask: net.CIDRMask(32, 32)},
					})))

				session, err = DeleteContainer(netconf, netnspath)
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				// TODO - Should just use the etcd API
				session, err = gexec.Start(exec.Command("bash", "-c", EtcdGetCommand(endpoint_path)), GinkgoWriter, GinkgoWriter)
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit(4)) //Exit 4 means the key didn't exist

				// Make sure the interface has been removed from the namespace
				targetNs, _ := ns.GetNS(netnspath)
				err = targetNs.Do(func(_ ns.NetNS) error {
					_, err = netlink.LinkByName("eth0")
					return err
				})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(Equal("Link not found"))

				// Make sure the interface has been removed from the host
				_, err = netlink.LinkByName("cali" + containerID)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(Equal("Link not found"))

			})
		})
	})
})
