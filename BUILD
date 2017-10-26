load("@io_bazel_rules_go//go:def.bzl", "gazelle", "go_binary", "go_library", "go_prefix")

go_prefix("tigera.io/dikastes")

gazelle(name = "gazelle")

go_library(
    name = "go_default_library",
    srcs = ["dikastes.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//proto:go_default_library",
        "//server:go_default_library",
        "@com_github_docopt_docopt_go//:go_default_library",
        "//vendor/github.com/projectcalico/libcalico-go/lib/api:go_default_library",
        "@com_github_sirupsen_logrus//:go_default_library",
        "@io_k8s_apimachinery//pkg/util/validation:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//reflection:go_default_library",
        "@com_github_spiffe_spire//pkg/agent/auth:go_default_library",
    ],
)

go_binary(
    name = "dikastes",
    library = ":go_default_library",
    visibility = ["//visibility:public"],
)
