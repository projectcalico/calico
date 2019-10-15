module github.com/projectcalico/kube-controllers

go 1.12

require (
	cloud.google.com/go v0.38.0 // indirect
	github.com/apparentlymart/go-cidr v1.0.1
	github.com/coreos/etcd v3.3.15+incompatible
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/gophercloud/gophercloud v0.1.0 // indirect
	github.com/joho/godotenv v1.3.0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627
	github.com/projectcalico/felix v0.0.0-20190909220014-9e5ec5eca469
	github.com/projectcalico/libcalico-go v0.0.0-20191014173613-3dc8f2c35936
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/pflag v1.0.3
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-20191005115622-2e41325d9e4b
	k8s.io/apimachinery v0.0.0-20191006235458-f9f2f3f8ab02
	k8s.io/apiserver v0.0.0-20191008120233-c29386a6051d
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v0.0.0-20180627202928-fc9bbf2f57995271c5cd6911ede7a2ebc5ea7c6f
