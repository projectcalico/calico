module github.com/projectcalico/kube-controllers

go 1.12

require (
	cloud.google.com/go v0.0.0-20160913182117-3b1ae45394a2 // indirect
	github.com/Azure/go-autorest v11.1.0+incompatible // indirect
	github.com/coreos/etcd v3.3.10+incompatible
	github.com/dgrijalva/jwt-go v3.0.0+incompatible // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-ini/ini v1.39.0 // indirect
	github.com/go-playground/locales v0.12.1 // indirect
	github.com/go-playground/universal-translator v0.0.0-20170327191703-71201497bace // indirect
	github.com/golang/groupcache v0.0.0-20190702054246-869f871628b6 // indirect
	github.com/google/btree v0.0.0-20161005200959-925471ac9e21 // indirect
	github.com/gophercloud/gophercloud v0.0.0-20190126172459-c818fa66e4c8 // indirect
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/imdario/mergo v0.3.5 // indirect
	github.com/joho/godotenv v1.3.0
	github.com/json-iterator/go v0.0.0-20180701071628-ab8a2e0c74be // indirect
	github.com/kardianos/osext v0.0.0-20170510131534-ae77be60afb1 // indirect
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/leodido/go-urn v0.0.0-20181204092800-a67a23e1c1af // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/onsi/ginkgo v1.6.0
	github.com/onsi/gomega v0.0.0-20190113212917-5533ce8a0da3
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627
	github.com/projectcalico/felix v0.0.0-20190419061543-3774b6b48ee7
	github.com/projectcalico/go-json v0.0.0-20161128004156-6219dc7339ba // indirect
	github.com/projectcalico/go-yaml v0.0.0-20161201183616-955bc3e451ef // indirect
	github.com/projectcalico/go-yaml-wrapper v0.0.0-20161127220527-598e54215bee // indirect
	github.com/projectcalico/libcalico-go v0.0.0-20190807202433-7be0d765781f
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.2.0
	github.com/smartystreets/goconvey v0.0.0-20190731233626-505e41936337 // indirect
	github.com/spf13/pflag v1.0.1
	golang.org/x/oauth2 v0.0.0-20170412232759-a6bd8cefa181 // indirect
	golang.org/x/sys v0.0.0-20190312061237-fead79001313 // indirect
	golang.org/x/text v0.3.1-0.20181227161524-e6919f6577db // indirect
	golang.org/x/time v0.0.0-20170420181420-c06e80d9300e // indirect
	google.golang.org/appengine v1.5.0 // indirect
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
	gopkg.in/go-playground/validator.v9 v9.27.0 // indirect
	gopkg.in/inf.v0 v0.9.0 // indirect
	gopkg.in/ini.v1 v1.46.0 // indirect
	k8s.io/api v0.0.0-20190419092548-c5cad27821f6
	k8s.io/apimachinery v0.0.0-20190419212445-b874eabb9a4e
	k8s.io/apiserver v0.0.0-20190423173055-cc449ec47086
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/klog v0.3.0
)

replace (
	k8s.io/api => k8s.io/api v0.0.0-20190409021203-6e4e0e4f393b
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190404173353-6a84e37a896d
	k8s.io/client-go => k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
)
