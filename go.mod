module github.com/projectcalico/typha

go 1.16

require (
	github.com/Workiva/go-datastructures v1.0.50
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/go-ini/ini v0.0.0-20190327024845-3be5ad479f69
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/mipearson/rfw v0.0.0-20170619235010-6f0a6f3266ba
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.1
	github.com/projectcalico/api v0.0.0-20211027233830-6b11a0f525e1
	github.com/projectcalico/libcalico-go v1.7.2-0.20211028190301-9b43eae22410
	github.com/prometheus/client_golang v1.4.0
	github.com/sirupsen/logrus v1.4.2
	golang.org/x/tools v0.1.2 // indirect
	k8s.io/api v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v0.21.0
)

replace (
	github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7
)
