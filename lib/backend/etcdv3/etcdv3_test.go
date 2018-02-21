package etcdv3_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/backend/etcdv3"
)

var _ = Describe("RulesAPIToBackend", func() {
	It("should raise an error if specified certs don't exist", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/fake/path",
			EtcdCertFile:   "/fake/path",
			EtcdKeyFile:    "/fake/path",
			EtcdEndpoints:  "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})

	It("shouldn't create a client with empty certs", func() {
		_, err := etcdv3.NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdCACertFile: "/dev/null",
			EtcdCertFile:   "/dev/null",
			EtcdKeyFile:    "/dev/null",
			EtcdEndpoints:  "http://fake:2379",
		})

		Expect(err).To(HaveOccurred())
	})
})
