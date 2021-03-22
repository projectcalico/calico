module github.com/projectcalico/cni-plugin

go 1.13

require (
	github.com/alexflint/go-filemutex v0.0.0-20171022225611-72bdc8eae2ae // indirect
	github.com/containernetworking/cni v0.0.0-20180705210735-e67bb289cccf
	github.com/containernetworking/plugins v0.0.0-20180925020009-646dbbace1b1
	github.com/coreos/go-iptables v0.3.0 // indirect
	github.com/gogo/protobuf v1.2.2-0.20190723190241-65acae22fc9d
	github.com/mcuadros/go-version v0.0.0-20190308113854-92cdf37c5b75
	github.com/natefinch/atomic v0.0.0-20150920032501-a62ce929ffcc
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/projectcalico/libcalico-go v1.7.2-0.20210322201452-322f3f8be4fd
	github.com/safchain/ethtool v0.0.0-20170622225139-7ff1ba29eca2 // indirect
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/vishvananda/netlink v0.0.0-20170630184320-6e453822d85e
	github.com/vishvananda/netns v0.0.0-20170219233438-54f0e4339ce7 // indirect
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	google.golang.org/grpc v1.23.1

	// k8s.io/api v1.16.3 is at 16d7abae0d2a
	k8s.io/api v0.17.2

	// k8s.io/apimachinery 1.16.3 is at 72ed19daf4bb
	k8s.io/apimachinery v0.17.2

	// k8s.io/client-go 1.16.3 is at 6c5935290e33
	k8s.io/client-go v0.17.2
)
