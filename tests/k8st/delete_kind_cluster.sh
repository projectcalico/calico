#!/bin/bash -e

# test directory.
TEST_DIR=./tests/k8st

# kind binary.
: ${KIND:=$TEST_DIR/kind}

${KIND} delete cluster
rm $TEST_DIR/kind
rm $TEST_DIR/infra/calico.yaml
