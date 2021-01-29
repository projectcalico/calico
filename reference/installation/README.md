# Generating API reference docs

The api.html doc in this directory is generated using https://github.com/tmjd/gen-crd-api-reference-docs/tree/kb_v2.

To generate an updated file, run `make build-operator-reference OPERATOR_VERSION=<operator_branch>` using
the operator_branch that deploys the components that go with the docs version.
