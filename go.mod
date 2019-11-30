module github.com/kelseyhightower/confd

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/google/btree v0.0.0-20180813153112-4030bb1f1f0c // indirect
	github.com/kelseyhightower/memkv v0.1.1
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/projectcalico/confd v3.2.0+incompatible // indirect
	github.com/projectcalico/libcalico-go v1.7.2-0.20191127160841-0216c08ec5bf
	github.com/projectcalico/typha v0.7.3-0.20191129094908-d54e8b003c9f
	github.com/sirupsen/logrus v1.4.2
	github.com/ugorji/go v1.1.7 // indirect
	k8s.io/api v0.0.0-20191121175643-4ed536977f46
	k8s.io/apimachinery v0.0.0-20191121175448-79c2a76c473a
	k8s.io/client-go v0.0.0-20190620085101-78d2af792bab
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
