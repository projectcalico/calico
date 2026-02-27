module github.com/projectcalico/calico

go 1.25.7

require (
	cloud.google.com/go/storage v1.57.1
	github.com/BurntSushi/toml v1.5.0
	github.com/DeRuina/timberjack v1.3.9
	github.com/Masterminds/semver/v3 v3.4.0
	github.com/Microsoft/hcsshim v0.13.0
	github.com/apparentlymart/go-cidr v1.1.0
	github.com/approvals/go-approval-tests v1.6.0
	github.com/aws/aws-sdk-go-v2 v1.39.5
	github.com/aws/aws-sdk-go-v2/config v1.31.16
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.12
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.259.0
	github.com/aws/smithy-go v1.23.1
	github.com/bits-and-blooms/bitset v1.24.2
	github.com/buger/jsonparser v1.1.1
	github.com/container-storage-interface/spec v1.9.0
	github.com/containernetworking/cni v1.3.0
	github.com/containernetworking/plugins v1.9.0
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/docker/distribution v2.8.3+incompatible
	github.com/docker/docker v28.5.1+incompatible
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/envoyproxy/go-control-plane/envoy v1.35.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/gavv/monotime v0.0.0-20190418164738-30dba4353424
	github.com/go-ini/ini v1.67.0
	github.com/go-logr/logr v1.4.3
	github.com/gofrs/flock v0.13.0
	github.com/gogo/googleapis v1.4.1
	github.com/golang/snappy v1.0.0
	github.com/google/btree v1.1.3
	github.com/google/go-cmp v0.7.0
	github.com/google/go-containerregistry v0.20.3
	github.com/google/go-github/v53 v53.2.0
	github.com/google/netstack v0.0.0-20191123085552-55fcc16cd0eb
	github.com/google/safetext v0.0.0-20240722112252-5a72de7e7962
	github.com/google/uuid v1.6.0
	github.com/gopacket/gopacket v1.4.0
	github.com/gruntwork-io/terratest v0.52.0
	github.com/hashicorp/yamux v0.1.2
	github.com/ishidawataru/sctp v0.0.0-20250829011129-4b890084db30
	github.com/jinzhu/copier v0.4.0
	github.com/joho/godotenv v1.5.1
	github.com/json-iterator/go v1.1.12
	github.com/juju/clock v1.1.1
	github.com/juju/errors v1.0.0
	github.com/juju/mutex v0.0.0-20180619145857-d21b13acf4bf
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/kelseyhightower/memkv v0.1.1
	github.com/libp2p/go-reuseport v0.4.0
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
	github.com/mipearson/rfw v0.0.0-20170619235010-6f0a6f3266ba
	github.com/natefinch/atomic v1.0.1
	github.com/nmrshll/go-cp v0.0.0-20180115193924-61436d3b7cfa
	github.com/olekukonko/tablewriter v0.0.5
	github.com/onsi/ginkgo/v2 v2.28.1
	github.com/onsi/gomega v1.39.1
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/projectcalico/api v0.0.0-20220722155641-439a754a988b
	github.com/projectcalico/calico/lib/httpmachinery v0.0.0-00010101000000-000000000000
	github.com/projectcalico/calico/lib/std v0.0.0-00010101000000-000000000000
	github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/client_model v0.6.2
	github.com/prometheus/common v0.67.2
	github.com/prometheus/procfs v0.19.2
	github.com/safchain/ethtool v0.6.2
	github.com/shirou/gopsutil/v4 v4.25.9
	github.com/sirupsen/logrus v1.9.3
	github.com/slack-go/slack v0.17.3
	github.com/snowzach/rotatefilehook v0.0.0-20220211133110-53752135082d
	github.com/spf13/cast v1.10.0
	github.com/spf13/cobra v1.10.1
	github.com/spf13/pflag v1.0.10
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.11.1
	github.com/tchap/go-patricia/v2 v2.3.3
	github.com/termie/go-shutil v0.0.0-20140729215957-bcacb06fecae
	github.com/tigera/operator/api v0.0.0-20250807130954-d4353da6554e
	github.com/urfave/cli/v3 v3.3.8
	github.com/vishvananda/netlink v1.3.1
	go.etcd.io/etcd/api/v3 v3.6.5
	go.etcd.io/etcd/client/pkg/v3 v3.6.5
	go.etcd.io/etcd/client/v2 v2.305.24
	go.etcd.io/etcd/client/v3 v3.6.5
	go.yaml.in/yaml/v3 v3.0.4
	golang.org/x/mod v0.32.0
	golang.org/x/net v0.49.0
	golang.org/x/oauth2 v0.34.0
	golang.org/x/sync v0.19.0
	golang.org/x/sys v0.40.0
	golang.org/x/text v0.33.0
	golang.org/x/time v0.14.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.10
	gopkg.in/go-playground/validator.v9 v9.30.2
	gopkg.in/yaml.v3 v3.0.1
	helm.sh/helm/v3 v3.19.0
	k8s.io/api v0.34.3
	k8s.io/apiextensions-apiserver v0.34.3
	k8s.io/apimachinery v0.34.3
	k8s.io/apiserver v0.34.3
	k8s.io/client-go v0.34.3
	k8s.io/component-base v0.34.3
	k8s.io/klog/v2 v2.130.1
	k8s.io/kube-aggregator v0.34.3
	k8s.io/kube-openapi v0.31.0
	k8s.io/kubernetes v1.34.3
	k8s.io/utils v0.0.0-20250604170112-4c0f3b243397
	modernc.org/memory v1.11.0
	sigs.k8s.io/controller-runtime v0.22.3
	sigs.k8s.io/kind v0.30.0
	sigs.k8s.io/knftables v0.0.19
	sigs.k8s.io/network-policy-api v0.1.8-0.20260212153203-412bf65729a5
	sigs.k8s.io/yaml v1.6.0
)

require (
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.6.0 // indirect
	github.com/openshift/custom-resource-status v1.1.2 // indirect
	kubevirt.io/containerized-data-importer-api v1.63.1 // indirect
	kubevirt.io/controller-lifecycle-operator-sdk/api v0.0.0-20220329064328-f3cc58c6ed90 // indirect
)

require (
	golang.org/x/crypto v0.47.0 // indirect
	kubevirt.io/api v1.7.0
	kubevirt.io/client-go v1.7.0
)

require (
	al.essio.dev/pkg/shellescape v1.5.1 // indirect
	cel.dev/expr v0.24.0 // indirect
	cloud.google.com/go v0.121.6 // indirect
	cloud.google.com/go/auth v0.16.5 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.8.0 // indirect
	cloud.google.com/go/iam v1.5.2 // indirect
	cloud.google.com/go/monitoring v1.24.2 // indirect
	cyphar.com/go-pathrs v0.2.1 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.29.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.53.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.53.0 // indirect
	github.com/JeffAshton/win_pdh v0.0.0-20161109143554-76bb4ee9f0ab // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hnslib v0.1.1 // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/ProtonMail/go-crypto v1.0.0 // indirect
	github.com/alexflint/go-filemutex v1.3.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/armon/circbuf v0.0.0-20190214190532-5111143e8da2 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.7 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.18.20 // indirect
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.17.41 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/acm v1.30.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.51.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.44.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.37.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecr v1.36.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecs v1.52.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/iam v1.38.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.4.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.10.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.37.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/lambda v1.69.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/rds v1.91.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.46.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.69.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.34.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sns v1.33.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sqs v1.37.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssm v1.56.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.39.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/cncf/xds/go v0.0.0-20250501225837-2ac532fd4443 // indirect
	github.com/containerd/cgroups/v3 v3.0.3 // indirect
	github.com/containerd/containerd/api v1.8.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.16.3 // indirect
	github.com/containerd/ttrpc v1.2.6 // indirect
	github.com/containerd/typeurl/v2 v2.2.2 // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.6.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.6 // indirect
	github.com/cyphar/filepath-securejoin v0.6.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v27.5.0+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.8.2 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.9.0 // indirect
	github.com/emicklei/go-restful/v3 v3.12.2 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/euank/go-kmsg-parser v2.0.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.9.11 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.10 // indirect
	github.com/go-errors/errors v1.4.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-playground/form v3.1.4+incompatible // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.28.0 // indirect
	github.com/go-sql-driver/mysql v1.8.1 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/gonvenience/bunt v1.3.5 // indirect
	github.com/gonvenience/neat v1.3.12 // indirect
	github.com/gonvenience/term v1.0.2 // indirect
	github.com/gonvenience/text v1.0.7 // indirect
	github.com/gonvenience/wrap v1.1.2 // indirect
	github.com/gonvenience/ytbx v1.4.4 // indirect
	github.com/google/cadvisor v0.52.1 // indirect
	github.com/google/cel-go v0.26.0 // indirect
	github.com/google/gnostic-models v0.7.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20260115054156-294ebfa9ad83 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.1 // indirect
	github.com/gruntwork-io/go-commons v0.8.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/homeport/dyff v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.7.1 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/karrick/godirwalk v1.17.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/libopenstorage/openstorage v1.0.0 // indirect
	github.com/lithammer/dedent v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-ciede2000 v0.0.0-20170301095244-782e8c62fec3 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mattn/go-zglob v0.0.2-0.20190814121620-e3c945676326 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/mistifyio/go-zfs v2.1.2-0.20190413222219-f784269be439+incompatible // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/mitchellh/hashstructure v1.1.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/spdystream v0.5.0 // indirect
	github.com/moby/sys/atomicwriter v0.1.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/opencontainers/cgroups v0.0.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.2.0 // indirect
	github.com/opencontainers/selinux v1.13.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/pquerna/otp v1.4.0 // indirect
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.80.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spiffe/go-spiffe/v2 v2.5.0 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/texttheater/golang-levenshtein v1.0.1 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/urfave/cli v1.22.16 // indirect
	github.com/vbatts/tar-split v0.11.6 // indirect
	github.com/virtuald/go-ordered-json v0.0.0-20170621173500-b18e6e673d74 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.36.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/github.com/emicklei/go-restful/otelrestful v0.46.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.37.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.37.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.opentelemetry.io/proto/otlp v1.7.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93 // indirect
	golang.org/x/term v0.39.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	google.golang.org/api v0.247.0 // indirect
	google.golang.org/genproto v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250818200422-3122310a409c // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/cloud-provider v0.34.3 // indirect
	k8s.io/component-helpers v0.34.3 // indirect
	k8s.io/controller-manager v0.34.3 // indirect
	k8s.io/cri-api v0.34.3 // indirect
	k8s.io/cri-client v0.34.3 // indirect
	k8s.io/csi-translation-lib v0.34.3 // indirect
	k8s.io/dynamic-resource-allocation v0.34.3 // indirect
	k8s.io/kms v0.34.3 // indirect
	k8s.io/kube-scheduler v0.34.3 // indirect
	k8s.io/kubectl v0.34.3 // indirect
	k8s.io/kubelet v0.34.3 // indirect
	k8s.io/mount-utils v0.34.3 // indirect
	k8s.io/pod-security-admission v0.34.3
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.34.0 // indirect
	sigs.k8s.io/json v0.0.0-20241014173422-cfa47c3a1cc8 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
)

replace (
	github.com/projectcalico/api => ./api
	github.com/projectcalico/calico/lib/httpmachinery => ./lib/httpmachinery
	github.com/projectcalico/calico/lib/std => ./lib/std

	// Need replacements for all the k8s subsidiary projects that are pulled in indirectly because
	// the kubernets repo pulls them in via a replacement to its own vendored copies, which doesn't work for
	// transient imports.
	k8s.io/api => k8s.io/api v0.34.3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.34.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.34.3
	k8s.io/apiserver => k8s.io/apiserver v0.34.3
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.34.3
	k8s.io/client-go => k8s.io/client-go v0.34.3
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.34.3
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.34.3
	k8s.io/code-generator => k8s.io/code-generator v0.34.3
	k8s.io/component-base => k8s.io/component-base v0.34.3
	k8s.io/component-helpers => k8s.io/component-helpers v0.34.3
	k8s.io/controller-manager => k8s.io/controller-manager v0.34.3
	k8s.io/cri-api => k8s.io/cri-api v0.34.3
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.34.3
	k8s.io/endpointslice => k8s.io/endpointslice v0.34.3
	k8s.io/externaljwt => k8s.io/externaljwt v0.34.3
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.34.3
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.34.3

	// kubevirt.io/client-go requires a tagged kube-openapi version that doesn't
	// exist; pin to the pseudo-version used by the rest of our k8s dependencies.
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20250710124328-f3f2b991d03b
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.34.3
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.34.3
	k8s.io/kubectl => k8s.io/kubectl v0.34.3
	k8s.io/kubelet => k8s.io/kubelet v0.34.3
	k8s.io/metrics => k8s.io/metrics v0.34.3
	k8s.io/mount-utils => k8s.io/mount-utils v0.34.3
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.34.3
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.34.3

	kubevirt.io/client-go => github.com/tigera/kubevirt-client-go v1.7.0-tigera1
)
