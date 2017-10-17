load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "check.go",
        "match.go",
        "server.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//proto:go_default_library",
        "//vendor/github.com/projectcalico/libcalico-go/lib/api:go_default_library",
        "//vendor/github.com/projectcalico/libcalico-go/lib/client:go_default_library",
        "//vendor/github.com/projectcalico/libcalico-go/lib/selector:go_default_library",
        "@com_github_sirupsen_logrus//:go_default_library",
        "@org_golang_x_net//context:go_default_library",
    ],
)
