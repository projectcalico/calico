module github.com/projectcalico/node

go 1.12

require (
	github.com/coreos/etcd v3.3.13+incompatible // indirect
	github.com/dgrijalva/jwt-go v3.0.0+incompatible // indirect
	github.com/gophercloud/gophercloud v0.4.0 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/kelseyhightower/confd v0.0.0-00010101000000-000000000000
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/projectcalico/felix v0.0.0-20200106213856-d7c6d615fb7b
	github.com/projectcalico/libcalico-go v1.7.2-0.20191223230708-3d65d3751012
	github.com/projectcalico/typha v0.7.3-0.20200103001756-52c554096ce9 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7
	k8s.io/api v0.0.0-20191003000013-35e20aa79eb8
	k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/client-go v12.0.0+incompatible
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v0.0.0-20180627202928-fc9bbf2f57995271c5cd6911ede7a2ebc5ea7c6f

replace github.com/kelseyhightower/confd => github.com/projectcalico/confd v1.0.1-0.20200103010707-42b94537d756
