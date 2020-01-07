module github.com/projectcalico/kube-controllers

go 1.12

require (
	github.com/coreos/etcd v3.3.15+incompatible
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/joho/godotenv v1.3.0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627
	github.com/projectcalico/felix v0.0.0-20200106213856-d7c6d615fb7b
	github.com/projectcalico/libcalico-go v1.7.2-0.20191223230708-3d65d3751012
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/pflag v1.0.3
	k8s.io/api v0.0.0-20191010143144-fbf594f18f80
	k8s.io/apimachinery v0.0.0-20191006235458-f9f2f3f8ab02
	k8s.io/apiserver v0.0.0-20191010200905-b803d9d0d3eb
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
)
