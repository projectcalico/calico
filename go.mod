module github.com/projectcalico/cni-plugin

go 1.14

require (
	github.com/Microsoft/go-winio v0.4.15-0.20190919025122-fc70bd9a86b5 // indirect
	github.com/Microsoft/hcsshim v0.8.6
	github.com/buger/jsonparser v1.0.0
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.8.5
	github.com/gogo/protobuf v1.2.2-0.20190723190241-65acae22fc9d
	github.com/howeyc/fsnotify v0.9.0
	github.com/juju/clock v0.0.0-20190205081909-9c5c9712527c
	github.com/juju/errors v0.0.0-20200330140219-3fe23663418f
	github.com/juju/mutex v0.0.0-20180619145857-d21b13acf4bf
	github.com/juju/testing v0.0.0-20200608005635-e4eedbc6f7aa // indirect
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/mcuadros/go-version v0.0.0-20190308113854-92cdf37c5b75
	github.com/natefinch/atomic v0.0.0-20150920032501-a62ce929ffcc
	github.com/nmrshll/go-cp v0.0.0-20180115193924-61436d3b7cfa
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.1
	github.com/projectcalico/libcalico-go v1.7.2-0.20201119205058-b367043ede58
	github.com/prometheus/common v0.4.1
	github.com/rakelkar/gonetsh v0.0.0-20190930180311-e5c5ffe4bdf0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/vishvananda/netlink v0.0.0-20181108222139-023a6dafdcdf
	go.etcd.io/etcd v0.5.0-alpha.5.0.20200401174654-e694b7bb0875
	golang.org/x/net v0.0.0-20200520004742-59133d7f0dd7
	golang.org/x/sys v0.0.0-20200519105757-fe76b779f299
	google.golang.org/grpc v1.23.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0

	// k8s.io/api v1.16.3 is at 16d7abae0d2a
	k8s.io/api v0.17.3

	// k8s.io/apimachinery 1.16.3 is at 72ed19daf4bb
	k8s.io/apimachinery v0.17.3

	// k8s.io/client-go 1.16.3 is at 6c5935290e33
	k8s.io/client-go v0.17.3
	k8s.io/utils v0.0.0-20191114200735-6ca3b61696b6
)
