module github.com/projectcalico/kube-controllers

go 1.13

require (
	github.com/Azure/go-autorest v13.3.0+incompatible // indirect
	github.com/apparentlymart/go-cidr v1.0.1
	github.com/coreos/etcd v3.3.15+incompatible
	github.com/joho/godotenv v1.3.0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627
	github.com/projectcalico/felix v0.0.0-20191122063206-5ef23057d939
	github.com/projectcalico/go-yaml v0.0.0-20161201183616-955bc3e451ef // indirect
	github.com/projectcalico/libcalico-go v1.7.2-0.20191122034129-d601846715fa
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/pflag v1.0.3
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v1 v1.0.0-20140924161607-9f9df34309c0 // indirect
	k8s.io/api v0.0.0-20191005115622-2e41325d9e4b
	k8s.io/apimachinery v0.0.0-20191006235458-f9f2f3f8ab02
	k8s.io/apiserver v0.0.0-20191008120233-c29386a6051d
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
