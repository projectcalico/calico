module github.com/projectcalico/node

go 1.12

require (
	github.com/coreos/etcd v3.3.13+incompatible // indirect
	github.com/kelseyhightower/confd v0.0.0-00010101000000-000000000000
	github.com/kelseyhightower/memkv v0.1.1 // indirect
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/projectcalico/felix v0.0.0-20190830001837-7753943d5841
	github.com/projectcalico/libcalico-go v0.0.0-20190822155120-15c0fc659f30
	github.com/projectcalico/typha v0.0.0-20190829203445-96045911fce7
	github.com/sirupsen/logrus v1.4.0
	github.com/ugorji/go/codec v1.1.7
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	k8s.io/api v0.0.0-20180628040859-072894a440bd
	k8s.io/apimachinery v0.0.0-20180621070125-103fd098999d
	k8s.io/client-go v8.0.0+incompatible
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v0.0.0-20180627202928-fc9bbf2f57995271c5cd6911ede7a2ebc5ea7c6f

replace github.com/kelseyhightower/confd => github.com/projectcalico/confd v0.0.0-20190726194724-4e1d8b2f7914
