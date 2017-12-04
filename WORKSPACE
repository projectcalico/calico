workspace(name = "proto_udsupsver_colabsaumoh")

git_repository(
    name = "io_bazel_rules_go",
    remote = "https://github.com/bazelbuild/rules_go.git",
    commit = "3930b2cdd78a896cae3c6d25b6e3e3b7ea7b8128"
)

load("@io_bazel_rules_go//go:def.bzl", "go_rules_dependencies", "go_register_toolchains")
go_rules_dependencies()
go_register_toolchains()

git_repository(
	name = "org_pubref_rules_protobuf",
	remote = "https://github.com/pubref/rules_protobuf.git",
	commit = "563b674a2ce6650d459732932ea2bc98c9c9a9bf"
)
load("@org_pubref_rules_protobuf//protobuf:rules.bzl", "proto_repositories")

proto_repositories()

load("@org_pubref_rules_protobuf//go:rules.bzl", "go_proto_repositories")

go_proto_repositories()
