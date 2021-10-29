module github.com/projectcalico/calicoctl/v3

go 1.16

require (
	github.com/StackExchange/wmi v0.0.0-20181212234831-e0a55b97c705 // indirect
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/eapache/channels v1.1.0 // indirect
	github.com/eapache/queue v0.0.0-20180227141424-093482f3f8ce // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/influxdata/influxdb v0.0.0-20190102202943-dd481f35df2c // indirect
	github.com/influxdata/platform v0.0.0-20190117200541-d500d3cf5589 // indirect
	github.com/mcuadros/go-version v0.0.0-20190308113854-92cdf37c5b75
	github.com/olekukonko/tablewriter v0.0.0-20190409134802-7e037d187b0c
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.1
	github.com/osrg/gobgp v0.0.0-20170802061517-bbd1d99396fe
	github.com/projectcalico/api v0.0.0-20211102181812-edfaf495a5c8
	github.com/projectcalico/go-json v0.0.0-20161128004156-6219dc7339ba
	github.com/projectcalico/go-yaml-wrapper v0.0.0-20191112210931-090425220c54
	github.com/projectcalico/libcalico-go v1.7.2-0.20211102193334-45c7e116840b
	github.com/shirou/gopsutil v0.0.0-20190323131628-2cbc9195c892
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/termie/go-shutil v0.0.0-20140729215957-bcacb06fecae
	github.com/vishvananda/netlink v0.0.0-20180501223456-f07d9d5231b9 // indirect
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	golang.org/x/tools v0.1.2 // indirect
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637 // indirect
	k8s.io/apiextensions-apiserver v0.18.12
	k8s.io/apimachinery v0.22.0
	k8s.io/client-go v0.22.0
)

replace (
	github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7
)
