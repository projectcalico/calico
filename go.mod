module github.com/projectcalico/node

go 1.12

require (
	github.com/gxed/GoEndian v0.0.0-20160916112711-0f5c6873267e // indirect
	github.com/gxed/eventfd v0.0.0-20160916113412-80a92cca79a8 // indirect
	github.com/ipfs/go-log v0.0.0-20180611222144-5dc2060baaf8 // indirect
	github.com/kelseyhightower/confd v0.0.0-00010101000000-000000000000
	github.com/libp2p/go-sockaddr v0.0.0-20190411201116-52957a0228cc // indirect
	github.com/mattn/go-colorable v0.0.0-20190708054220-c52ace132bf4 // indirect
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/projectcalico/felix v0.0.0-20200116081457-49ac9a8e4de7 // indirect
	github.com/projectcalico/libcalico-go v1.7.2-0.20200111004125-f4cc1f8914f8
	github.com/sirupsen/logrus v1.4.2
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	github.com/whyrusleeping/go-logging v0.0.0-20170515211332-0457bb6b88fc // indirect
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7

	// k8s.io/api v1.16.3 is at 16d7abae0d2a
	k8s.io/api v0.0.0-20191114100352-16d7abae0d2a

	// k8s.io/apimachinery 1.16.3 is at 72ed19daf4bb
	k8s.io/apimachinery v0.0.0-20191028221656-72ed19daf4bb

	// k8s.io/client-go 1.16.3 is at 6c5935290e33
	k8s.io/client-go v0.0.0-20191114101535-6c5935290e33
)

replace (
	github.com/kelseyhightower/confd => github.com/projectcalico/confd v0.0.0-20200111080717-1627ca0e171b
	github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
)
