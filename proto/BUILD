load("@io_bazel_rules_go//proto:def.bzl", "go_grpc_library")

go_grpc_library(
    name = "go_default_library",
    proto = ":authz_proto",
    visibility = ["//visibility:public"],
    importpath = "tigera.io/dikastes/proto",
)

proto_library(
    name = "authz_proto",
    srcs = ["authz.proto"],
)