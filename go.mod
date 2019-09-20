module github.com/projectcalico/kube-controllers

go 1.12

require (
	github.com/Azure/go-autorest v11.1.0+incompatible // indirect
	github.com/apparentlymart/go-cidr v1.0.1
	github.com/coreos/etcd v3.3.10+incompatible
	github.com/gophercloud/gophercloud v0.0.0-20190126172459-c818fa66e4c8 // indirect
	github.com/imdario/mergo v0.3.5 // indirect
	github.com/joho/godotenv v1.3.0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627
	github.com/projectcalico/felix v0.0.0-20190909220014-9e5ec5eca469
	github.com/projectcalico/libcalico-go v0.0.0-20190919175705-6dc16419eb4d
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/pflag v1.0.3
	k8s.io/api v0.0.0-20190419092548-c5cad27821f6
	k8s.io/apimachinery v0.0.0-20190419212445-b874eabb9a4e
	k8s.io/apiserver v0.0.0-20190423173055-cc449ec47086
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/klog v0.4.0
)

replace (
	github.com/sirupsen/logrus => github.com/projectcalico/logrus v0.0.0-20180627202928-fc9bbf2f57995271c5cd6911ede7a2ebc5ea7c6f
	k8s.io/api => k8s.io/api v0.0.0-20190409021203-6e4e0e4f393b
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190404173353-6a84e37a896d
	k8s.io/client-go => k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
)
