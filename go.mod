module github.com/kelseyhightower/confd

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/kelseyhightower/memkv v0.1.1
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/projectcalico/libcalico-go v0.0.0-20200206230134-a508550ad9b4
	github.com/projectcalico/typha v0.0.0-20200122112911-d8ebd2e88f93
	github.com/sirupsen/logrus v1.4.2
	github.com/ugorji/go v1.1.7 // indirect

	// k8s.io/api v1.16.3 is at 16d7abae0d2a
	k8s.io/api v0.0.0-20191114100352-16d7abae0d2a

	// k8s.io/apimachinery 1.16.3 is at 72ed19daf4bb
	k8s.io/apimachinery v0.0.0-20191028221656-72ed19daf4bb

	// k8s.io/client-go 1.16.3 is at 6c5935290e33
	k8s.io/client-go v0.0.0-20191114101535-6c5935290e33
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
