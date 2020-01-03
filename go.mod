module github.com/projectcalico/node

go 1.12

require (
	github.com/Workiva/go-datastructures v1.0.50 // indirect
	github.com/beorn7/perks v1.0.0 // indirect
	github.com/coreos/etcd v3.3.18+incompatible // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/kelseyhightower/memkv v0.1.1 // indirect
	github.com/mailru/easyjson v0.0.0-20190626092158-b2ccc519800e // indirect
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/projectcalico/felix v0.0.0-20191231175915-5ccf52a034de // indirect
	github.com/projectcalico/libcalico-go v1.7.2-0.20191214003639-2449a6f3ad4f
	github.com/projectcalico/typha v0.7.2 // indirect
	github.com/prometheus/client_model v0.0.0-20190129233127-fd36f4220a90 // indirect
	github.com/prometheus/common v0.0.0-20190416093430-c873fb1f9420 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	go.uber.org/zap v1.13.0 // indirect
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7
	gopkg.in/go-playground/validator.v9 v9.28.0 // indirect

	// k8s.io/api v1.16.3 is at 16d7abae0d2a
	k8s.io/api v0.0.0-20191114100352-16d7abae0d2a

	// k8s.io/apimachinery 1.16.3 is at 72ed19daf4bb
	k8s.io/apimachinery v0.0.0-20191028221656-72ed19daf4bb

	// k8s.io/client-go 1.16.3 is at 6c5935290e33
	k8s.io/client-go v0.0.0-20191114101535-6c5935290e33
)

replace (
	github.com/kelseyhightower/confd => github.com/projectcalico/confd v0.0.0-20200101080735-5d0283b1e793
	github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
)
