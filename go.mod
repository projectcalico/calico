module github.com/projectcalico/cni-plugin

go 1.14

require (
	github.com/Microsoft/hcsshim v0.8.6
	github.com/buger/jsonparser v1.0.0
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.8.5
	github.com/gofrs/flock v0.8.0
	github.com/gogo/protobuf v1.3.2
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
	github.com/projectcalico/api v0.0.0-20210727230154-ae822ba06c23
	github.com/projectcalico/libcalico-go v1.7.2-0.20210727232737-a62724233980
	github.com/prometheus/common v0.9.1
	github.com/rakelkar/gonetsh v0.0.0-20190930180311-e5c5ffe4bdf0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/vishvananda/netlink v0.0.0-20181108222139-023a6dafdcdf
	go.etcd.io/etcd v0.5.0-alpha.5.0.20201125193152-8a03d2e9614b
	golang.org/x/net v0.0.0-20210224082022-3d97a244fca7
	golang.org/x/sys v0.0.0-20210225134936-a50acf3fe073
	google.golang.org/grpc v1.27.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	k8s.io/api v0.21.0-rc.0
	k8s.io/apimachinery v0.21.0-rc.0
	k8s.io/client-go v0.21.0-rc.0
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
)

replace github.com/Microsoft/hcsshim => github.com/projectcalico/hcsshim v0.8.9-calico
