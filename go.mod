module github.com/projectcalico/felix

go 1.13

require (
	github.com/containernetworking/cni v0.5.2
	github.com/davecgh/go-spew v1.1.1
	github.com/docopt/docopt-go v0.0.0-20160216232012-784ddc588536
	github.com/go-ini/ini v1.44.0
	github.com/gobuffalo/packr/v2 v2.5.2
	github.com/gogo/protobuf v1.2.2-0.20190723190241-65acae22fc9d
	github.com/golang/protobuf v1.3.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0 // indirect
	github.com/gxed/GoEndian v0.0.0-20160916112711-0f5c6873267e // indirect
	github.com/gxed/eventfd v0.0.0-20160916113412-80a92cca79a8 // indirect
	github.com/hashicorp/go-version v1.2.0
	github.com/ipfs/go-log v0.0.0-20180611222144-5dc2060baaf8 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/libp2p/go-reuseport v0.0.0-20180924121034-dd0c37d7767b
	github.com/libp2p/go-sockaddr v0.0.0-20190411201116-52957a0228cc // indirect
	github.com/mattn/go-colorable v0.0.0-20190708054220-c52ace132bf4 // indirect
	github.com/mipearson/rfw v0.0.0-20170619235010-6f0a6f3266ba
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/opentracing/opentracing-go v0.0.0-20190704175813-135aa78c6f95 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/projectcalico/libcalico-go v1.7.2-0.20191202205659-0e3dbc013255
	github.com/projectcalico/pod2daemon v0.0.0-20190730210055-df57fc59e2e1
	github.com/projectcalico/typha v0.7.3-0.20191203041907-730197037195
	github.com/prometheus/client_golang v0.9.1
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/smartystreets/goconvey v0.0.0-20190731233626-505e41936337 // indirect
	github.com/ugorji/go v1.1.7 // indirect
	github.com/vishvananda/netlink v0.0.0-20180501223456-f07d9d5231b9
	github.com/vishvananda/netns v0.0.0-20160430053723-8ba1072b58e0 // indirect
	github.com/whyrusleeping/go-logging v0.0.0-20170515211332-0457bb6b88fc // indirect
	go.uber.org/atomic v1.4.0 // indirect
	go.uber.org/multierr v1.1.0 // indirect
	go.uber.org/zap v1.10.0 // indirect
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	golang.org/x/sys v0.0.0-20190826190057-c7b8b68b1456
	google.golang.org/grpc v1.19.0
	gopkg.in/ini.v1 v1.46.0 // indirect
	k8s.io/api v0.0.0-20191121175643-4ed536977f46
	k8s.io/apimachinery v0.0.0-20191121175448-79c2a76c473a
	k8s.io/client-go v0.0.0-20190620085101-78d2af792bab
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
