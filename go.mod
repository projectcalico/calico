module github.com/projectcalico/kube-controllers

go 1.12

require (
	github.com/apparentlymart/go-cidr v1.0.1
	github.com/coreos/etcd v3.3.13+incompatible
	github.com/joho/godotenv v1.3.0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627
	github.com/projectcalico/felix v0.0.0-20200103181800-6474231ca9d5
	github.com/projectcalico/libcalico-go v1.7.2-0.20191223230650-31f24eab280c
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/pflag v1.0.3
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-20190627205229-acea843d18eb
	k8s.io/apimachinery v0.0.0-20190629005116-7ae370969693
	// Pin to a version of apiserver that does not depend on gopkg.in/yaml.v1
	k8s.io/apiserver v0.0.0-20190629005904-7ad4fb8dd3f0
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v0.4.0
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v0.0.0-20180627202928-fc9bbf2f5799
