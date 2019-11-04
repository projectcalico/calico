module github.com/projectcalico/cni-plugin

go 1.12

require (
	github.com/alexflint/go-filemutex v0.0.0-20171022225611-72bdc8eae2ae // indirect
	github.com/containernetworking/cni v0.0.0-20180705210735-e67bb289cccf
	github.com/containernetworking/plugins v0.0.0-20180925020009-646dbbace1b1
	github.com/coreos/go-iptables v0.3.0 // indirect
	github.com/mcuadros/go-version v0.0.0-20190308113854-92cdf37c5b75
	github.com/natefinch/atomic v0.0.0-20150920032501-a62ce929ffcc
	github.com/onsi/ginkgo v1.6.0
	github.com/onsi/gomega v1.4.2
	github.com/projectcalico/libcalico-go v0.0.0-20191104213956-8f81e1e344ce
	github.com/safchain/ethtool v0.0.0-20170622225139-7ff1ba29eca2 // indirect
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/vishvananda/netlink v0.0.0-20170630184320-6e453822d85e
	github.com/vishvananda/netns v0.0.0-20170219233438-54f0e4339ce7 // indirect
	k8s.io/api v0.0.0-20190620084959-7cf5895f2711
	k8s.io/apimachinery v0.0.0-20190612205821-1799e75a0719
	k8s.io/client-go v12.0.0+incompatible
)
