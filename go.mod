module github.com/projectcalico/felix

go 1.15

require (
	github.com/Microsoft/hcsshim v0.8.9
	github.com/aws/aws-sdk-go v1.35.7
	github.com/containernetworking/cni v0.8.0 // indirect
	github.com/containernetworking/plugins v0.8.2
	github.com/davecgh/go-spew v1.1.1
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/go-ini/ini v1.44.0
	github.com/gogo/protobuf v1.3.1
	github.com/golang-collections/collections v0.0.0-20130729185459-604e922904d3
	github.com/golang/groupcache v0.0.0-20190702054246-869f871628b6 // indirect
	github.com/golang/protobuf v1.4.2
	github.com/google/gopacket v1.1.17
	github.com/google/netstack v0.0.0-20191123085552-55fcc16cd0eb
	github.com/ishidawataru/sctp v0.0.0-20191218070446-00ab2ac2db07
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/kr/text v0.2.0 // indirect
	github.com/libp2p/go-reuseport v0.0.1
	github.com/mipearson/rfw v0.0.0-20170619235010-6f0a6f3266ba
	github.com/mitchellh/go-homedir v1.1.0
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1
	github.com/projectcalico/libcalico-go v1.7.2-0.20210305184916-02db57c95742
	github.com/projectcalico/pod2daemon v0.0.0-20210303175725-63bffe4262de
	github.com/projectcalico/typha v0.7.3-0.20210305191109-86f3147c19f1
	github.com/prometheus/client_golang v1.0.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.6.1
	github.com/stretchr/testify v1.5.1 // indirect
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.org/x/tools v0.0.0-20200502202811-ed308ab3e770 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20200324154536-ceff61240acf
	google.golang.org/genproto v0.0.0-20191203220235-3fa9dbf08042 // indirect
	google.golang.org/grpc v1.27.0
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	honnef.co/go/tools v0.0.1-2020.1.3 // indirect
	k8s.io/api v0.19.6
	k8s.io/apimachinery v0.19.6
	k8s.io/client-go v0.19.6
	k8s.io/kubernetes v1.18.12
)

replace (
	github.com/Microsoft/hcsshim => github.com/projectcalico/hcsshim v0.8.9-calico
	github.com/sirupsen/logrus => github.com/projectcalico/logrus v0.0.0-20180701205716-fc9bbf2f5799

	// Need replacements for all the k8s subsidiary projects that are pulled in indirectly because
	// the kubernets repo pulls them in via a replacement to its own vendored copies, which doesn't work for
	// transient imports.
	k8s.io/api => k8s.io/api v0.18.12
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.18.12
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.12
	k8s.io/apiserver => k8s.io/apiserver v0.18.12
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.18.12
	k8s.io/client-go => k8s.io/client-go v0.18.12
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.18.12
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.18.12
	k8s.io/code-generator => k8s.io/code-generator v0.18.12
	k8s.io/component-base => k8s.io/component-base v0.18.12
	k8s.io/cri-api => k8s.io/cri-api v0.18.12
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.18.12
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.18.12
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.18.12
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.18.12
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.18.12
	k8s.io/kubectl => k8s.io/kubectl v0.18.12
	k8s.io/kubelet => k8s.io/kubelet v0.18.12
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.18.12
	k8s.io/metrics => k8s.io/metrics v0.18.12
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.18.12
)
