load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")
load("@org_pubref_rules_protobuf//go:rules.bzl", "GRPC_COMPILE_DEPS")

go_binary(
    name = "flexvol",
    srcs = ["flexvoldriver.go"],
    visibility = ["//visibility:public"],
    deps = [
	"//protos/mgmtintf_v1:go_default_library",
	"//nodeagentmgmt:go_default_library",
        "@com_github_spf13_cobra//:go_default_library",
    ] + GRPC_COMPILE_DEPS,
)
