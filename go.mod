module github.com/kelseyhightower/confd

go 1.15

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/kelseyhightower/memkv v0.1.1
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.1
	github.com/projectcalico/api v0.0.0-20210721205409-e5769c6ea695
	github.com/projectcalico/libcalico-go v1.7.2-0.20210727203459-ee7ab0f86bf2
	github.com/projectcalico/typha v0.7.3-0.20210727205518-453c8787a541
	github.com/sirupsen/logrus v1.4.2
	k8s.io/api v0.21.0-rc.0
	k8s.io/apimachinery v0.21.0-rc.0
	k8s.io/client-go v0.21.0-rc.0
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
