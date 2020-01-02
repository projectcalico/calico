module github.com/projectcalico/kube-controllers

go 1.13

require (
	github.com/apparentlymart/go-cidr v1.0.1
	github.com/coreos/etcd v3.3.18+incompatible
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/joho/godotenv v1.3.0
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/mailru/easyjson v0.0.0-20190626092158-b2ccc519800e // indirect
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627
	github.com/projectcalico/felix v0.0.0-20191231175915-5ccf52a034de // indirect
	github.com/projectcalico/libcalico-go v1.7.2-0.20191214003639-2449a6f3ad4f
	github.com/projectcalico/typha v0.7.2 // indirect
	github.com/prometheus/client_golang v0.9.4 // indirect
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/pflag v1.0.5
	go.uber.org/zap v1.13.0 // indirect
	gopkg.in/go-playground/validator.v9 v9.28.0 // indirect

	// k8s.io/api v1.16.3 is at 16d7abae0d2a
	k8s.io/api v0.0.0-20191114100352-16d7abae0d2a

	// k8s.io/apimachinery 1.16.3 is at 72ed19daf4bb
	k8s.io/apimachinery v0.0.0-20191028221656-72ed19daf4bb

	// k8s.io/apiserver 1.16.3 is at 9ca1dc586682
	k8s.io/apiserver v0.0.0-20191114103151-9ca1dc586682

	// k8s.io/client-go 1.16.3 is at 6c5935290e33
	k8s.io/client-go v0.0.0-20191114101535-6c5935290e33
	k8s.io/klog v1.0.0
)

replace github.com/sirupsen/logrus => github.com/projectcalico/logrus v1.0.4-calico
