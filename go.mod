module github.com/kelseyhightower/confd

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/aws/aws-sdk-go v1.22.1 // indirect
	github.com/garyburd/redigo v1.6.0 // indirect
	github.com/hashicorp/consul/api v1.1.0 // indirect
	github.com/hashicorp/vault/api v1.0.4 // indirect
	github.com/kelseyhightower/memkv v0.1.1
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/projectcalico/confd v3.2.0+incompatible // indirect
	github.com/projectcalico/libcalico-go v0.0.0-20191104214504-aa6a608ee1fe
	github.com/projectcalico/typha v0.0.0-20191104234117-ab7cc2290b27
	github.com/samuel/go-zookeeper v0.0.0-20190801204459-3c104360edc8 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/ugorji/go v1.1.7 // indirect
	github.com/xordataexchange/crypt v0.0.2 // indirect
	k8s.io/api v0.0.0-20190620084959-7cf5895f2711
	k8s.io/apimachinery v0.0.0-20190612205821-1799e75a0719
	k8s.io/client-go v12.0.0+incompatible
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v0.0.0-20180627202928-fc9bbf2f57995271c5cd6911ede7a2ebc5ea7c6f
