module github.com/projectcalico/node

go 1.12

require (
	github.com/coreos/etcd v3.3.13+incompatible // indirect
	github.com/kelseyhightower/confd v0.16.0
	github.com/mattn/go-isatty v0.0.8 // indirect
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/projectcalico/felix v0.0.0-20191008064910-3286f617f736
	github.com/projectcalico/libcalico-go v0.0.0-20191006160109-16b05e93ecfd
	github.com/sirupsen/logrus v1.4.2
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	k8s.io/api v0.0.0-20180628040859-072894a440bd
	k8s.io/apimachinery v0.0.0-20180621070125-103fd098999d
	k8s.io/client-go v8.0.0+incompatible
)

replace (
	github.com/kelseyhightower/confd => github.com/projectcalico/confd v0.0.0-20191008042421-f72fb251ecf1
	github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
)
