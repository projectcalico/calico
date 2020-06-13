module github.com/kelseyhightower/confd

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.18+incompatible // indirect
	github.com/kelseyhightower/memkv v0.1.1
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/philhofer/fwd v1.0.0 // indirect
	github.com/pquerna/ffjson v0.0.0-20190813045741-dac163c6c0a9 // indirect
	github.com/projectcalico/libcalico-go v1.7.2-0.20200612144350-cf86bf004498
	github.com/projectcalico/typha v0.7.3-0.20200613040728-2701a071aa71
	github.com/sirupsen/logrus v1.4.2
	github.com/tinylib/msgp v1.1.0 // indirect
	github.com/ugorji/go v0.0.0-20171019201919-bdcc60b419d1 // indirect

	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/client-go v0.17.2
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
