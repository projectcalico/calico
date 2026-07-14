#!/usr/bin/env bash
# run_tests.sh (release-v3.32) - build and run the in-repo e2e binary, or defer
# to bz tests.
#
# release-v3.32 has no `make e2e-run` target and no structured E2E_TEST_CONFIG
# (both are master-only). Selection matches v3.32's Semaphore body_standard.sh:
#   - RUN_LOCAL_TESTS set → build the e2e binary from local source and run it
#     via ginkgo, selecting specs with K8S_E2E_FLAGS (regex focus/skip). On
#     v3.32 only the `windows` pipeline sets RUN_LOCAL_TESTS.
#   - Else → `bz tests`. This is the path every scheduled e2e pipeline
#     (iptables/bpf/nftables/upgrade/aws/aks/certification/…) takes; bz runs the
#     k8s-e2e suite and produces the JUnit report itself.
#
# Required env:
#   BZ_LOCAL_DIR, BZ_LOGS_DIR, HOME, REPORT_DIR, TEST_TYPE
#
# Sourced from body_*.sh. Exits with the test exit code.

for _var in BZ_LOCAL_DIR BZ_LOGS_DIR HOME REPORT_DIR TEST_TYPE; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

if [[ -n "${RUN_LOCAL_TESTS:-}" ]]; then
  # Build the e2e binary from the local source tree.
  echo "[INFO] building e2e binary from local source..."
  pushd "${CI_HOME}/${CI_GIT_DIR}" || exit
  make -C e2e build |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/${TEST_TYPE}-build.log.gz")

  # Run in the same calico/go-build image used to compile the binary (it has
  # the libbpf/libelf/libz runtime deps and uuidgen the e2e scripts need).
  GO_BUILD_VER=$(make --no-print-directory -f ./metadata.mk -f - <<<'print:; @echo $(GO_BUILD_VER)' print)
  RUN_IMAGE="calico/go-build:${GO_BUILD_VER}"

  # The upstream k8s e2e framework shells out to `kubectl` for any
  # exec-into-pod step (RunHostCmd, etc.), so kubectl must be on PATH inside
  # the runner. Fetch a K8S_VERSION-pinned binary via the repo's `make
  # kubectl` target; it lands in hack/test/kind/ which is bind-mounted into
  # the container, and we prepend that to PATH inside the bash -c below.
  make kubectl

  # EKS kubeconfigs exec aws-iam-authenticator (PATH lookup); the aws-eks
  # provisioner installs it on the host, so bind-mount it when present (no-op
  # otherwise). It also needs AWS creds in the container; mount ~/.aws (written
  # by the prologue) and point the SDK at it -- container runs as an arbitrary UID.
  auth_mount=()
  aws_cred_env=()
  if [[ -x "${BZ_LOCAL_DIR}/bin/aws-iam-authenticator" ]]; then
    auth_mount=(-v "${BZ_LOCAL_DIR}/bin/aws-iam-authenticator:/usr/local/bin/aws-iam-authenticator:ro")
    if [[ -d "${HOME}/.aws" ]]; then
      auth_mount+=(-v "${HOME}/.aws:/aws-config:ro")
      aws_cred_env=(-e AWS_SHARED_CREDENTIALS_FILE=/aws-config/credentials
                    -e AWS_CONFIG_FILE=/aws-config/config
                    -e "AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}")
    fi
  fi

  echo "[INFO] starting e2e tests (ginkgo, K8S_E2E_FLAGS=${K8S_E2E_FLAGS:-<none>})..."
  # --junit-report writes report/junit.xml for the epilogue to publish. (v3.32's
  # Semaphore relied on bz for JUnit; the local-binary path emits it directly.)
  # K8S_E2E_FLAGS holds multiple ginkgo args and is intentionally word-split.
  # Capture the exit code so the JUnit copy below runs even when tests fail.
  e2e_rc=0
  # shellcheck disable=SC2086
  docker run --rm --init --net=host \
    -e LOCAL_USER_ID="$(id -u)" \
    -e GOCACHE=/go-cache \
    -e GOPATH=/go \
    -e KUBECONFIG=/kubeconfig \
    -e PRODUCT=${PRODUCT:-calico} \
    -e CREATE_WINDOWS_NODES \
    -e FUNCTIONAL_AREA \
    -e INSTALLER \
    -e PROVISIONER \
    -e K8S_VERSION \
    -e DATAPLANE \
    -e ENCAPSULATION_TYPE \
    -e WINDOWS_OS \
    -e USE_VENDORED_CNI \
    ${K8S_E2E_DOCKER_EXTRA_FLAGS:-} \
    "${auth_mount[@]}" \
    "${aws_cred_env[@]}" \
    -v "$(pwd)":/go/src/github.com/projectcalico/calico:rw \
    -v "$(pwd)"/.go-pkg-cache:/go-cache:rw \
    -v "${BZ_LOCAL_DIR}/kubeconfig:/kubeconfig:ro" \
    -w /go/src/github.com/projectcalico/calico \
    "${RUN_IMAGE}" \
    bash -c "export PATH=/go/src/github.com/projectcalico/calico/hack/test/kind:\$PATH && \
      git config --global --add safe.directory '*' && \
      mkdir -p report && \
      go run github.com/onsi/ginkgo/v2/ginkgo -procs=${E2E_PROCS:-4} \
        --junit-report=junit.xml --output-dir=report/ \
        ./e2e/bin/k8s/e2e.test -- ${K8S_E2E_FLAGS}" \
    |& tee "${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log" || e2e_rc=$?

  # Copy JUnit XML to REPORT_DIR so the epilogue publishes it.
  mkdir -p "${REPORT_DIR}"
  cp report/junit.xml "${REPORT_DIR}/junit.xml" 2>/dev/null || true
  popd || exit

  # Propagate the original test exit code.
  exit ${e2e_rc}
else
  # Scheduled e2e (RUN_LOCAL_TESTS unset) and non-e2e test types (benchmarks,
  # certification, etc.) -- defer to bz, which runs the suite and writes JUnit.
  echo "[INFO] starting bz testing (K8S_E2E_FLAGS=${K8S_E2E_FLAGS:-<none>})..."
  bz tests ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log.gz")
fi
