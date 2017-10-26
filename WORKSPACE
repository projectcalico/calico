workspace(name = "com_github_tigera_dikastes")

git_repository(
    name = "io_bazel_rules_go",
    commit = "eba68677493422112dd25f6a0b4bbdb02387e5a4",  # Aug 1, 2017
    remote = "https://github.com/bazelbuild/rules_go.git",
)

load("@io_bazel_rules_go//go:def.bzl", "go_repositories", "go_repository")

go_repositories()

git_repository(
    name = "org_pubref_rules_protobuf",
    commit = "9ede1dbc38f0b89ae6cd8e206a22dd93cc1d5637",  # Mar 31, 2017 (gogo* support)
    remote = "https://github.com/pubref/rules_protobuf",
)

load("@org_pubref_rules_protobuf//protobuf:rules.bzl", "proto_repositories")

proto_repositories()

go_repository(
    name = "com_github_gogo_protobuf",
    commit = "c0656edd0d9eab7c66d1eb0c568f9039345796f7",
    importpath = "github.com/gogo/protobuf",
)

go_repository(
    name = "com_github_docopt_docopt_go",
    commit = "784ddc588536785e7299f7272f39101f7faccc3f",
    importpath = "github.com/docopt/docopt-go",
)

go_repository(
    name = "com_github_sirupsen_logrus",
    commit = "ba1b36c82c5e05c4f912a88eab0dcd91a171688f",
    importpath = "github.com/sirupsen/logrus",
)

go_repository(
    name = "org_golang_x_net",
    commit = "66aacef3dd8a676686c7ae3716979581e8b03c47",
    importpath = "golang.org/x/net",
)

go_repository(
    name = "org_golang_google_grpc",
    commit = "2be1bca94fda955ac10e314fd6b69526b1f92400",
    importpath = "google.golang.org/grpc",
)

go_repository(
    name = "org_golang_google_genproto",
    commit = "ee236bd376b077c7a89f260c026c4735b195e459",
    importpath = "google.golang.org/genproto"
)

go_repository(
    name = "com_github_golang_protobuf",
    importpath = "github.com/golang/protobuf",
    commit = "17ce1425424ab154092bbb43af630bd647f3bb0d",
)

go_repository(
    name = "com_github_golang_glog",
    commit = "23def4e6c14b4da8ac2ed8007337bc5eb5007998",
    importpath = "github.com/golang/glog",
)

go_repository(
    name = "com_github_spiffe_spire",
    importpath = "github.com/spiffe/spire",
    commit = "c5479abc0cced444c3e968d21eb0b92d681ad56b",
)

# Libcalico and its deps

go_repository(
    name = "com_google_cloud_go",
    importpath = "cloud.google.com/go",
    commit = "3b1ae45394a234c385be014e9a488f2bb6eef821",
)

go_repository(
    name = "com_github_beorn7_perks",
    importpath = "github.com/beorn7/perks",
    commit = "4c0e84591b9aa9e6dcfdf3e020114cd81f89d5f9",
)

go_repository(
    name = "com_github_coreos_etcd",
    importpath = "github.com/coreos/etcd",
    commit = "17ae440991da3bdb2df4309936dd2074f66ec394",
)

go_repository(
    name = "com_github_coreos_go_oidc",
    importpath = "github.com/coreos/go-oidc",
    commit = "be73733bb8cc830d0205609b95d125215f8e9c70",
)

go_repository(
    name = "com_github_coreos_go_semver",
    importpath = "github.com/coreos/go-semver",
    commit = "568e959cd89871e61434c1143528d9162da89ef2",
)

go_repository(
    name = "com_github_coreos_pkg",
    importpath = "github.com/coreos/pkg",
    commit = "3ac0863d7acf3bc44daf49afef8919af12f704ef",
)

go_repository(
    name = "com_github_davecgh_go_spew",
    importpath = "github.com/davecgh/go-spew",
    commit = "5215b55f46b2b919f50a1df0eaa5886afe4e3b3d",
)

go_repository(
    name = "com_github_docker_distribution",
    importpath = "github.com/docker/distribution",
    commit = "cd27f179f2c10c5d300e6d09025b538c475b0d51",
)

go_repository(
    name = "com_github_emicklei_go_restful",
    importpath = "github.com/emicklei/go-restful",
    commit = "09691a3b6378b740595c1002f40c34dd5f218a22",
)

go_repository(
    name = "com_github_ghodss_yaml",
    importpath = "github.com/ghodss/yaml",
    commit = "73d445a93680fa1a78ae23a5839bad48f32ba1ee",
)

go_repository(
    name = "com_github_go_openapi_jsonpointer",
    importpath = "github.com/go-openapi/jsonpointer",
    commit = "46af16f9f7b149af66e5d1bd010e3574dc06de98",
)

go_repository(
    name = "com_github_go_openapi_jsonreference",
    importpath = "github.com/go-openapi/jsonreference",
    commit = "13c6e3589ad90f49bd3e3bbe2c2cb3d7a4142272",
)

go_repository(
    name = "com_github_go_openapi_spec",
    importpath = "github.com/go-openapi/spec",
    commit = "6aced65f8501fe1217321abf0749d354824ba2ff",
)

go_repository(
    name = "com_github_go_openapi_swag",
    importpath = "github.com/go-openapi/swag",
    commit = "1d0bd113de87027671077d3c71eb3ac5d7dbba72",
)

go_repository(
    name = "com_github_google_gofuzz",
    importpath = "github.com/google/gofuzz",
    commit = "44d81051d367757e1c7c6a5a86423ece9afcf63c",
)

go_repository(
    name = "com_github_howeyc_gopass",
    importpath = "github.com/howeyc/gopass",
    commit = "3ca23474a7c7203e0a0a070fd33508f6efdb9b3d",
)

go_repository(
    name = "com_github_imdario_mergo",
    importpath = "github.com/imdario/mergo",
    commit = "6633656539c1639d9d78127b7d47c622b5d7b6dc",
)

go_repository(
    name = "com_github_jonboulle_clockwork",
    importpath = "github.com/jonboulle/clockwork",
    commit = "2eee05ed794112d45db504eb05aa693efd2b8b09",
)

go_repository(
    name = "com_github_juju_ratelimit",
    importpath = "github.com/juju/ratelimit",
    commit = "77ed1c8a01217656d2080ad51981f6e99adaa177",
)

go_repository(
    name = "com_github_kelseyhightower_envconfig",
    importpath = "github.com/kelseyhightower/envconfig",
    commit = "91921eb4cf999321cdbeebdba5a03555800d493b",
)

go_repository(
    name = "com_github_mailru_easyjson",
    importpath = "github.com/mailru/easyjson",
    commit = "d5b7844b561a7bc640052f1b935f7b800330d7e0",
)

go_repository(
    name = "com_github_matttproud_golang_protobuf_extensions",
    importpath = "github.com/matttproud/golang_protobuf_extensions",
    commit = "c12348ce28de40eed0136aa2b644d0ee0650e56c",
)

go_repository(
    name = "com_github_onsi_ginkgo",
    importpath = "github.com/onsi/ginkgo",
    commit = "f40a49d81e5c12e90400620b6242fb29a8e7c9d9",
)

go_repository(
    name = "com_github_projectcalico_go_json",
    importpath = "github.com/projectcalico/go-json",
    commit = "6219dc7339ba20ee4c57df0a8baac62317d19cb1",
)

go_repository(
    name = "com_github_projectcalico_go_yaml",
    importpath = "github.com/projectcalico/go-yaml",
    commit = "955bc3e451ef0c9df8b9113bf2e341139cdafab2",
)

go_repository(
    name = "com_github_projectcalico_go_yaml_wrapper",
    importpath = "github.com/projectcalico/go-yaml-wrapper",
    commit = "598e54215bee41a19677faa4f0c32acd2a87eb56",
)

go_repository(
    name = "com_github_prometheus_client_golang",
    importpath = "github.com/prometheus/client_golang",
    commit = "c5b7fccd204277076155f10851dad72b76a49317",
)

go_repository(
    name = "com_github_prometheus_client_model",
    importpath = "github.com/prometheus/client_model",
    commit = "6f3806018612930941127f2a7c6c453ba2c527d2",
)

go_repository(
    name = "com_github_prometheus_common",
    importpath = "github.com/prometheus/common",
    commit = "61f87aac8082fa8c3c5655c7608d7478d46ac2ad",
)

go_repository(
    name = "com_github_prometheus_procfs",
    importpath = "github.com/prometheus/procfs",
    commit = "e645f4e5aaa8506fc71d6edbc5c4ff02c04c46f2",
)

go_repository(
    name = "com_github_PuerkitoBio_purell",
    importpath = "github.com/PuerkitoBio/purell",
    commit = "8a290539e2e8629dbc4e6bad948158f790ec31f4",
)

go_repository(
    name = "com_github_PuerkitoBio_urlesc",
    importpath = "github.com/PuerkitoBio/urlesc",
    commit = "5bd2802263f21d8788851d5305584c82a5c75d7e",
)

go_repository(
    name = "com_github_satori_go_uuid",
    importpath = "github.com/satori/go.uuid",
    commit = "b061729afc07e77a8aa4fad0a2fd840958f1942a",
)

go_repository(
    name = "com_github_sirupsen_logrus",
    importpath = "github.com/sirupsen/logrus",
    commit = "ba1b36c82c5e05c4f912a88eab0dcd91a171688f",
)

go_repository(
    name = "com_github_spf13_pflag",
    importpath = "github.com/spf13/pflag",
    commit = "08b1a584251b5b62f458943640fc8ebd4d50aaa5",
)

go_repository(
    name = "com_github_ugorji_go",
    importpath = "github.com/ugorji/go",
    commit = "ded73eae5db7e7a0ef6f55aace87a2873c5d2b74",
)

go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto",
    commit = "1351f936d976c60a0a48d728281922cf63eafb8d",
)

go_repository(
    name = "org_golang_x_oauth2",
    importpath = "golang.org/x/oauth2",
    commit = "3c3a985cb79f52a3190fbc056984415ca6763d01",
)

go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    commit = "8f0908ab3b2457e2e15403d3697c9ef5cb4b57a9",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    commit = "19e51611da83d6be54ddafce4a4af510cb3e9ea4",
)

go_repository(
    name = "org_golang_google_appengine",
    importpath = "google.golang.org/appengine",
    commit = "4f7eeb5305a4ba1966344836ba4af9996b7b4e05",
)

go_repository(
    name = "in_gopkg_go_playground_validator_v8",
    importpath = "gopkg.in/go-playground/validator.v8",
    commit = "5f57d2222ad794d0dffb07e664ea05e2ee07d60c",
)

go_repository(
    name = "in_gopkg_inf_v0",
    importpath = "gopkg.in/inf.v0",
    commit = "3887ee99ecf07df5b447e9b00d9c0b2adaa9f3e4",
)

go_repository(
    name = "in_gopkg_tchap_go_patricia_v2",
    importpath = "gopkg.in/tchap/go-patricia.v2",
    commit = "666120de432aea38ab06bd5c818f04f4129882c9",
)

go_repository(
    name = "in_gopkg_yaml_v2",
    importpath = "gopkg.in/yaml.v2",
    commit = "53feefa2559fb8dfa8d81baad31be332c97d6c77",
)

go_repository(
    name = "io_k8s_apimachinery",
    importpath = "k8s.io/apimachinery",
    commit = "b317fa7ec8e0e7d1f77ac63bf8c3ec7b29a2a215",
)

go_repository(
    name = "io_k8s_client_go",
    importpath = "k8s.io/client-go",
    commit = "4a3ab2f5be5177366f8206fd79ce55ca80e417fa",
)

go_repository(
    name = "com_github_onsi_gomega",
    importpath = "github.com/onsi/gomega",
    commit = "c893efa28eb45626cdaa76c9f653b62488858837",
)


