module github.com/projectcalico/node

go 1.12

require (
	github.com/coreos/etcd v3.3.13+incompatible // indirect
	github.com/kelseyhightower/confd v0.16.0
	github.com/mattn/go-isatty v0.0.8 // indirect
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/projectcalico/felix v0.0.0-20191002065209-add3576457f7
	github.com/projectcalico/libcalico-go v0.0.0-20191001220937-262b6a92960b
	github.com/projectcalico/typha v0.0.0-20191002041529-8a60973dd308
	github.com/sirupsen/logrus v1.4.2
	github.com/ugorji/go/codec v1.1.7
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	k8s.io/api v0.0.0-20180628040859-072894a440bd
	k8s.io/apimachinery v0.0.0-20180621070125-103fd098999d
	k8s.io/client-go v8.0.0+incompatible
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v0.0.0-20180627202928-fc9bbf2f57995271c5cd6911ede7a2ebc5ea7c6f

replace github.com/kelseyhightower/confd => github.com/projectcalico/confd v0.0.0-20190930204323-d41026f65c69
