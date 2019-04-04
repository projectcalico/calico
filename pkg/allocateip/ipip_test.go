package allocateip

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/projectcalico/libcalico-go/lib/net"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("determineIPIPEnabledPoolCIDRs", func() {
	log.SetOutput(os.Stdout)
	// Set log formatting.
	log.SetFormatter(&logutils.Formatter{})
	// Install a hook that adds file and line number information.
	log.AddHook(&logutils.ContextHook{})

	It("should match ip-pool-1 but not ip-pool-2", func() {
		// Mock out the node and ip pools
		n := api.Node{ObjectMeta: metav1.ObjectMeta{Name: "bee-node", Labels: map[string]string{"foo": "bar"}}}
		pl := api.IPPoolList{
			Items: []api.IPPool{
				api.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-1"},
					Spec: api.IPPoolSpec{
						Disabled:     false,
						CIDR:         "172.0.0.0/9",
						NodeSelector: `foo == "bar"`,
						IPIPMode:     api.IPIPModeAlways,
					},
				}, api.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-2"},
					Spec: api.IPPoolSpec{
						Disabled:     false,
						CIDR:         "172.128.0.0/9",
						NodeSelector: `foo != "bar"`,
						IPIPMode:     api.IPIPModeAlways,
					},
				}}}

		// Execute and test assertions.
		cidrs := determineIPIPEnabledPoolCIDRs(n, pl)
		_, cidr1, _ := net.ParseCIDR("172.0.0.1/9")
		_, cidr2, _ := net.ParseCIDR("172.128.0.1/9")
		Expect(cidrs).To(ContainElement(*cidr1))
		Expect(cidrs).ToNot(ContainElement(*cidr2))
	})
})
