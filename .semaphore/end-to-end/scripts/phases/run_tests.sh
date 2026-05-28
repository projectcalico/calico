#!/usr/bin/env bash
# run_tests.sh - acquire an e2e binary and run it, or defer to bz tests.
#
# Three modes, selected automatically:
#   1. RUN_LOCAL_TESTS is set  → build the e2e binary from local source
#      (per-PR CI / GCP e2e block).
#   2. TEST_TYPE == k8s-e2e    → download the pre-built binary from the
#      hashrelease (scheduled CI).
#   3. Otherwise               → fall back to `bz tests` for non-e2e test
#      types (benchmarks, certification, etc.).
#
# Required env:
#   BZ_LOCAL_DIR, BZ_LOGS_DIR, HOME, REPORT_DIR, TEST_TYPE
# Required for local builds:
#   E2E_TEST_CONFIG
# Required for hashrelease downloads:
#   RELEASE_STREAM
#
# Sourced from body_*.sh. Exits with the test exit code.

for _var in BZ_LOCAL_DIR BZ_LOGS_DIR HOME REPORT_DIR TEST_TYPE; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

if [[ -n "${RUN_LOCAL_TESTS:-}" ]]; then
  # Per-PR CI: build the e2e binary from the local source tree.
  echo "[INFO] building e2e binary from local source..."
  pushd "${HOME}/calico" || exit
  make -C e2e build |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/${TEST_TYPE}-build.log.gz")
  E2E_BINARY=/go/src/github.com/projectcalico/calico/e2e/bin/k8s/e2e.test
  popd || exit
elif [[ "${TEST_TYPE}" == "k8s-e2e" ]]; then
  # Scheduled CI: download the pre-built e2e binary from the hashrelease.
  echo "[INFO] downloading e2e binary from hashrelease..."
  HASHREL_URL=$(curl --retry 9 --retry-all-errors -sS "https://latest-os.docs.eng.tigera.net/${RELEASE_STREAM}.txt")
  echo "[INFO] hashrelease URL: ${HASHREL_URL}"
  ARCH=$(uname -m); [[ "$ARCH" == "x86_64" ]] && ARCH=amd64; [[ "$ARCH" == "aarch64" ]] && ARCH=arm64
  mkdir -p "${HOME}/calico/e2e/bin/k8s"
  curl --retry 9 --retry-all-errors -fsSL "${HASHREL_URL}/files/e2e/e2e-linux-${ARCH}.test" -o "${HOME}/calico/e2e/bin/k8s/e2e.test"
  chmod +x "${HOME}/calico/e2e/bin/k8s/e2e.test"
  echo "[INFO] downloaded e2e binary to ${HOME}/calico/e2e/bin/k8s/e2e.test"
  E2E_BINARY=/go/src/github.com/projectcalico/calico/e2e/bin/k8s/e2e.test
fi

if [[ -n "${E2E_BINARY:-}" ]]; then
  echo "[INFO] starting e2e tests..."
  pushd "${HOME}/calico" || exit

  # Pick a runtime image. The local-build path already pulled
  # calico/go-build to compile the binary, so reusing it for the run
  # step is free. The hashrelease path didn't compile anything, so
  # there's no reason to drag in the build toolchain -- use the
  # official golang image (debian-bookworm base, glibc-compatible
  # with the binary, ~800MB vs ~2GB).
  # The e2e binary is CGO-linked against libbpf and dynamically depends on
  # libelf and libz at runtime; the test scripts also call uuidgen. The
  # calico/go-build image already has these; the upstream golang:bookworm
  # image does not, so install them on the fly when using that path.
  PRE_RUN=":"
  if [[ -n "${RUN_LOCAL_TESTS:-}" ]]; then
    GO_BUILD_VER=$(make --no-print-directory -f ./metadata.mk -f - <<<'print:; @echo $(GO_BUILD_VER)' print)
    RUN_IMAGE="calico/go-build:${GO_BUILD_VER}"
  else
    GO_VERSION=$(make --no-print-directory -f ./metadata.mk -f - <<<'print:; @echo $(GO_VERSION)' print)
    RUN_IMAGE="golang:${GO_VERSION}-bookworm"
    PRE_RUN="apt-get update -qq && apt-get install -y --no-install-recommends libelf1 zlib1g uuid-runtime"
  fi

  # The upstream k8s e2e framework shells out to `kubectl` for any
  # exec-into-pod step (RunHostCmd, etc.), so kubectl must be on PATH inside
  # the runner. Fetch a K8S_VERSION-pinned binary via the repo's `make
  # kubectl` target; it lands in hack/test/kind/ which is bind-mounted into
  # the container, and we prepend that to PATH inside the bash -c below.
  make kubectl

  # Capture the exit code so the JUnit copy below runs even when tests fail
  # (set -e would otherwise bail out before the cp).
  e2e_rc=0
  docker run --rm --init --net=host \
    -e LOCAL_USER_ID="$(id -u)" \
    -e GOCACHE=/go-cache \
    -e GOPATH=/go \
    -e KUBECONFIG=/kubeconfig \
    -e PRODUCT=${PRODUCT:-calico} \
    ${K8S_E2E_DOCKER_EXTRA_FLAGS:-} \
    -v "$(pwd)":/go/src/github.com/projectcalico/calico:rw \
    -v "$(pwd)"/.go-pkg-cache:/go-cache:rw \
    -v "${BZ_LOCAL_DIR}/kubeconfig:/kubeconfig:ro" \
    -w /go/src/github.com/projectcalico/calico \
    "${RUN_IMAGE}" \
    bash -c "${PRE_RUN} && \
      export PATH=/go/src/github.com/projectcalico/calico/hack/test/kind:\$PATH && \
      git config --global --add safe.directory '*' && \
      make e2e-run \
        KUBECONFIG=/kubeconfig \
        E2E_TEST_CONFIG='${E2E_TEST_CONFIG}' \
        E2E_OUTPUT_DIR=report \
        E2E_JUNIT_REPORT=junit.xml" \
    |& tee "${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log" || e2e_rc=$?

  # Copy JUnit XML to REPORT_DIR so the epilogue publishes it.
  mkdir -p "${REPORT_DIR}"
  cp report/junit.xml "${REPORT_DIR}/junit.xml" 2>/dev/null || true
  popd || exit

  # Propagate the original test exit code.
  exit ${e2e_rc}
else
  # Non-e2e test types (benchmarks, certification, etc.) -- defer to bz.
  echo "[INFO] starting bz testing..."
  bz tests ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log.gz")
fi
