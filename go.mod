module github.com/projectcalico/felix

go 1.12

require (
	github.com/containernetworking/cni v0.5.2
	github.com/davecgh/go-spew v1.1.1
	github.com/docopt/docopt-go v0.0.0-20160216232012-784ddc588536
	github.com/go-ini/ini v1.44.0
	github.com/gobuffalo/packr/v2 v2.5.2
	github.com/gogo/protobuf v1.2.2-0.20190723190241-65acae22fc9d
	github.com/golang/protobuf v1.3.2
	github.com/hashicorp/go-version v1.2.0
	github.com/ishidawataru/sctp v0.0.0-20191218070446-00ab2ac2db07
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/libp2p/go-reuseport v0.0.1
	github.com/mipearson/rfw v0.0.0-20170619235010-6f0a6f3266ba
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/projectcalico/libcalico-go v0.0.0-20200212165426-dd72e0b33683
	github.com/projectcalico/pod2daemon v0.0.0-20191223184832-a0e1c4693271
	github.com/projectcalico/typha v0.0.0-20200213041052-b1fdcf41bcaa
	github.com/prometheus/client_golang v0.9.1
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/smartystreets/goconvey v0.0.0-20190731233626-505e41936337 // indirect
	github.com/vishvananda/netlink v0.0.0-20180501223456-f07d9d5231b9
	github.com/vishvananda/netns v0.0.0-20160430053723-8ba1072b58e0 // indirect
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	golang.org/x/sys v0.0.0-20190826190057-c7b8b68b1456
	google.golang.org/grpc v1.19.0
	gopkg.in/ini.v1 v1.46.0 // indirect

	// k8s.io/api v1.16.3 is at 16d7abae0d2a
	k8s.io/api v0.0.0-20191114100352-16d7abae0d2a

	// k8s.io/apimachinery 1.16.3 is at 72ed19daf4bb
	k8s.io/apimachinery v0.0.0-20191028221656-72ed19daf4bb

	// k8s.io/client-go 1.16.3 is at 6c5935290e33
	k8s.io/client-go v0.0.0-20191114101535-6c5935290e33
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
