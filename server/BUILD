load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "calicoquery.go",
        "check.go",
        "match.go",
        "server.go",
        "workload.go"
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//proto:go_default_library",
        "//vendor/github.com/projectcalico/libcalico-go/lib/api:go_default_library",
        "//vendor/github.com/projectcalico/libcalico-go/lib/client:go_default_library",
        "//vendor/github.com/projectcalico/libcalico-go/lib/selector:go_default_library",
        "//vendor/github.com/projectcalico/libcalico-go/lib/backend/k8s/resources:go_default_library",
        "//vendor/github.com/projectcalico/libcalico-go/lib/backend/model:go_default_library",
        "@com_github_sirupsen_logrus//:go_default_library",
        "@org_golang_x_net//context:go_default_library",
        "@io_k8s_client_go//kubernetes:go_default_library",
        "@io_k8s_client_go//rest:go_default_library",
        "@io_k8s_client_go//tools/clientcmd:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@com_github_spiffe_spire//pkg/agent/auth:go_default_library",
    ],
)
