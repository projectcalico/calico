package windataplane_test

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/dataplane-drivers/windataplane"
)

var _ = Describe("Constructor test", func() {
	var configParams *config.Config
	var dpConfig intdataplane.Config

	JustBeforeEach(func() {
		configParams = config.New()

		dpConfig := windataplane.Config{
			IPv6Enabled: configParams.Ipv6Support,
		}
	})

	It("should be constructable", func() {
		var dp = windataplane.NewWinDataplaneDriver(dpConfig)
		Expect(dp).ToNot(BeNil())
	})
})
