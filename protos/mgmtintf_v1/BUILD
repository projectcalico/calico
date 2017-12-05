load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("@org_pubref_rules_protobuf//go:rules.bzl", "go_proto_library")

go_proto_library(
    name = "protolib",
    protos = glob(["*.proto"]),
    verbose = 0,
    visibility = ["//visibility:public"],
    with_grpc = True,
    deps = [
    ],
)

go_library(
    name = "go_default_library",
    srcs = ["mgmtintf.pb.go"],
    importpath = "github.com/colabsaumoh/proto-udsuspver/protos/mgmtintf_v1",
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_x_net//context:go_default_library",
    ],
)
