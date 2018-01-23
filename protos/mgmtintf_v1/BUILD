load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("@org_pubref_rules_protobuf//go:rules.bzl", "go_proto_library", "GRPC_COMPILE_DEPS")

go_proto_library(
    name = "protolib",
    protos = glob(["*.proto"]),
    verbose = 1,
    visibility = ["//visibility:public"],
    with_grpc = True,
#
# Used to define how the generate pb.go file will generate the
# go import statement.
#
#
#    importmap = {
#        "google/rpc/status.proto": "google.golang.org/genproto/googleapis/rpc/status",
#    },

#
# The --proto_path option of protoc compiler.
# the external is-i think-the bazel magic of where the external .proto files are placed.
#
    imports = [
        "external/com_google_protobuf/src",
        "external/googleapi",
    ],
#
# any.proto and google/rpc/status.proto inclusing in the .proto file.
#
    inputs = [
        "@com_google_protobuf//:well_known_protos",
        "@googleapi//:rpc_status_protos_src",
    ],
#
# pb.go file dependencies
#
    deps = [
        "@org_golang_google_genproto//googleapis/rpc/status:go_default_library",
    ],
)

go_library(
    name = "go_default_library",
    srcs = ["mgmtintf.pb.go"],
    importpath = "github.com/colabsaumoh/proto-udsuspver/protos/mgmtintf_v1",
    visibility = ["//visibility:public"],
    deps = [
        ":protolib",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_x_net//context:go_default_library",
        "@org_golang_google_genproto//googleapis/rpc/status:go_default_library",
    ],
)
