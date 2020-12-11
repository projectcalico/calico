module github.com/kelseyhightower/confd

go 1.15

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/kelseyhightower/memkv v0.1.1
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.1
	github.com/projectcalico/libcalico-go v1.7.2-0.20201211095255-5d3be5f39c7c
	github.com/projectcalico/typha v0.7.3-0.20201211101419-55f54d6f1378
	github.com/sirupsen/logrus v1.4.2
	k8s.io/api v0.18.12
	k8s.io/apimachinery v0.18.12
	k8s.io/client-go v0.18.12
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
