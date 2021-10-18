module github.com/kelseyhightower/confd

go 1.16

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/kelseyhightower/memkv v0.1.1
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.1
	github.com/projectcalico/api v0.0.0-20211018181539-356e1052869a
	github.com/projectcalico/libcalico-go v1.7.2-0.20211018200233-b533a742a142
	github.com/projectcalico/typha v0.7.3-0.20211018210905-a1a1818fa7bd
	github.com/sirupsen/logrus v1.4.2
	gopkg.in/go-playground/validator.v9 v9.28.0 // indirect
	k8s.io/api v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v0.21.0
)

replace (
	github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7
)
