load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("@org_pubref_protobuf//go:rules.bzl", "GRPC_COMPILE_DEPS", "go_binary")

go_binary(
    name = "flexvoldriver",
    srcs = ["flexvoldriver.go"],
    deps = [
        ":protolib",
        "@com_github_spf13_cobra//:go_default_library",
    ] + GPRC_COMPILE_DEPS,
)

go_library(
    name = "go_default_library",
    srcs = ["flexvoldriver.go"],
    importpath = "colabsaumoh/proto-udsuspver/flexvol",
    visibility = ["//visibility:private"],
    deps = [
        "@com_github_colabsaumoh_proto_udsuspver//nodeagentmgmt:go_default_library",
        "@com_github_colabsaumoh_proto_udsuspver//protos/mgmtintf_v1:go_default_library",
        "@com_github_spf13_cobra//:go_default_library",
    ],
)

go_binary(
    name = "flexvol",
    embed = [":go_default_library"],
    importpath = "colabsaumoh/proto-udsuspver/flexvol",
    visibility = ["//visibility:public"],
)
