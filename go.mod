module github.com/projectcalico/kube-controllers

go 1.12

require (
	github.com/apparentlymart/go-cidr v1.0.1
	github.com/coreos/etcd v3.3.10+incompatible
	github.com/joho/godotenv v1.3.0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627
	github.com/projectcalico/felix v0.0.0-20190909220014-9e5ec5eca469
	github.com/projectcalico/libcalico-go v0.0.0-20191104213956-8f81e1e344ce
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/pflag v1.0.3
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-20190620084959-7cf5895f2711
	k8s.io/apimachinery v0.0.0-20190612205821-1799e75a0719
	k8s.io/apiserver v0.0.0-20190423173055-cc449ec47086
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v0.4.0
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v0.0.0-20180627202928-fc9bbf2f57995271c5cd6911ede7a2ebc5ea7c6f
