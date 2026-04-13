#!/usr/bin/env bash
# run_tests_local.sh - build the in-repo e2e binary and run it against the
# cluster at $BZ_LOCAL_DIR/kubeconfig.
#
# Wraps `make e2e-run` in calico/go-build so the build and test-run share
# the same toolchain version. The docker wrapper is legacy -- once the
# in-repo binary reaches parity with the enterprise suite, this can drop
# the wrapper and just call `make -C ${HOME}/calico e2e-run` directly.
#
# Required env:
#   BZ_LOCAL_DIR, BZ_LOGS_DIR, HOME, REPORT_DIR, TEST_TYPE, E2E_TEST_CONFIG
#
# Sourced from body_*.sh. Exits with the test binary's exit code.

echo "[INFO] starting e2e testing from local binary..."
pushd "${HOME}/calico"

make -C e2e build |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/${TEST_TYPE}-build.log.gz")
GO_BUILD_VER=$(grep '^GO_BUILD_VER=' ./metadata.mk | cut -d= -f2)

# Capture the exit code so the JUnit copy below runs even when tests fail
# (set -e would otherwise bail out before the cp).
e2e_rc=0
docker run --rm --init --net=host \
  -e LOCAL_USER_ID="$(id -u)" \
  -e GOCACHE=/go-cache \
  -e GOPATH=/go \
  -e KUBECONFIG=/kubeconfig \
  -e PRODUCT=calico \
  -e CREATE_WINDOWS_NODES \
  -e FUNCTIONAL_AREA \
  -e INSTALLER \
  -e PROVISIONER \
  -e K8S_VERSION \
  -e DATAPLANE \
  -e ENCAPSULATION_TYPE \
  -e WINDOWS_OS \
  -e USE_VENDORED_CNI \
  -v "$(pwd)":/go/src/github.com/projectcalico/calico:rw \
  -v "$(pwd)"/.go-pkg-cache:/go-cache:rw \
  -v "${BZ_LOCAL_DIR}/kubeconfig:/kubeconfig:ro" \
  -w /go/src/github.com/projectcalico/calico \
  "calico/go-build:${GO_BUILD_VER}" \
  make e2e-run \
    KUBECONFIG=/kubeconfig \
    E2E_TEST_CONFIG="${E2E_TEST_CONFIG}" \
    E2E_OUTPUT_DIR=report \
    E2E_JUNIT_REPORT=junit.xml \
  |& tee "${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log" || e2e_rc=$?

# Copy JUnit XML to REPORT_DIR so the epilogue publishes it.
mkdir -p "${REPORT_DIR}"
cp report/junit.xml "${REPORT_DIR}/junit.xml" 2>/dev/null || true
popd

# Propagate the original test exit code.
exit ${e2e_rc}
