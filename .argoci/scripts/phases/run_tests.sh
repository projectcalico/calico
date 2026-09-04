#!/usr/bin/env bash
# run_tests.sh (release-v3.32) - build and run the in-repo e2e binary, or defer
# to bz tests.
#
# release-v3.32 has no `make e2e-run` target and no structured E2E_TEST_CONFIG
# (both are master-only), so specs are selected with K8S_E2E_FLAGS regexes:
#   - RUN_LOCAL_TESTS set → build the e2e binary from local source. On v3.32
#     only the `windows` pipeline sets it.
#   - TEST_TYPE k8s-e2e → download the OSS e2e binary from the hashrelease.
#     This is the path the scheduled e2e pipelines take.
#   - Else (non-e2e test types: benchmarks, certification, …) → `bz tests`,
#     which runs the suite and produces the JUnit report itself.
#
# Required env:
#   BZ_LOCAL_DIR, BZ_LOGS_DIR, HOME, REPORT_DIR, TEST_TYPE
# Required for hashrelease downloads:
#   RELEASE_STREAM (or UPLEVEL_RELEASE_STREAM, which takes precedence)
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
  E2E_BINARY=e2e/bin/k8s/e2e.test
elif [[ "${TEST_TYPE}" == "k8s-e2e" ]]; then
  # Scheduled e2e: download the pre-built e2e binary from the hashrelease.
  echo "[INFO] downloading e2e binary from hashrelease..."
  pushd "${CI_HOME}/${CI_GIT_DIR}" || exit

  # Upgrade runs set RELEASE_STREAM to the downlevel version they install
  # first, but the tests run against the uplevel version.
  E2E_STREAM=${UPLEVEL_RELEASE_STREAM:-${RELEASE_STREAM}}
  if [[ -z "${E2E_STREAM}" ]]; then
    echo "[ERROR] neither UPLEVEL_RELEASE_STREAM nor RELEASE_STREAM is set; cannot resolve an e2e binary"
    exit 1
  fi
  E2E_STREAM_URL="https://latest-os.hashrelease.tools.tigera.net/${E2E_STREAM}.txt"
  # Assign inside `if` so the diagnostic below runs: this script is sourced under
  # `set -e`, where a bare command substitution would exit here instead.
  if ! HASHREL_URL=$(curl --retry 9 --retry-all-errors -fsS "${E2E_STREAM_URL}"); then
    echo "[ERROR] no hashrelease published for stream ${E2E_STREAM} at ${E2E_STREAM_URL}"
    exit 1
  fi
  echo "[INFO] hashrelease URL (stream ${E2E_STREAM}): ${HASHREL_URL}"

  ARCH=$(uname -m); [[ "$ARCH" == "x86_64" ]] && ARCH=amd64; [[ "$ARCH" == "aarch64" ]] && ARCH=arm64
  E2E_BINARY_URL="${HASHREL_URL}/files/e2e/e2e-linux-${ARCH}.test"
  mkdir -p e2e/bin/k8s
  # Fail loudly rather than falling back to a floating image, which would run a
  # suite built from another branch (and, for k8s-e2e:stable, another repo).
  if ! curl --retry 9 --retry-all-errors -fsSL "${E2E_BINARY_URL}" -o e2e/bin/k8s/e2e.test; then
    echo "[ERROR] no e2e binary published for stream ${E2E_STREAM} at ${E2E_BINARY_URL}"
    exit 1
  fi
  chmod +x e2e/bin/k8s/e2e.test
  E2E_BINARY=e2e/bin/k8s/e2e.test
fi

if [[ -n "${E2E_BINARY:-}" ]]; then
  # Run in calico/go-build: it has uuidgen and the ginkgo CLI the run below needs.
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

  # The go-build entrypoint creates a "user" account with
  # `useradd -u ${LOCAL_USER_ID}` and then re-execs the command through
  # `su-exec user`. ArgoCI runners execute as root, so LOCAL_USER_ID=0 makes
  # useradd fail ("UID 0 is not unique" -- root already owns it), su-exec cannot
  # resolve the account, and the container exits before ginkgo starts. The image
  # supports RUN_AS_ROOT to skip that path, so set it when we are already root.
  # Non-root runners (Semaphore agents) keep the existing behaviour.
  run_as_root_env=()
  if [[ "$(id -u)" -eq 0 ]]; then
    run_as_root_env=(-e RUN_AS_ROOT=true)
  fi

  echo "[INFO] starting e2e tests (ginkgo, K8S_E2E_FLAGS=${K8S_E2E_FLAGS:-<none>})..."
  # --junit-report writes report/junit.xml for the epilogue to publish. (v3.32's
  # Semaphore relied on bz for JUnit; the local-binary path emits it directly.)
  #
  # K8S_E2E_FLAGS and E2E_PROCS are passed as container env and expanded by the
  # CONTAINER's shell (after it parses the bash -c script), NOT interpolated by
  # the host into the script text. The flags contain unquoted regex parens
  # (e.g. --ginkgo.focus=(\[sig-calico\]...)); baking them into the script would
  # make the container shell re-parse them as syntax and die at parse time
  # (breaks the windows suite). Hence the single-quoted bash -c and -e passing.
  # K8S_E2E_FLAGS is intentionally unquoted inside so it word-splits into args.
  # Capture the exit code so the JUnit copy below runs even when tests fail.
  e2e_rc=0
  # shellcheck disable=SC2086
  docker run --rm --init --net=host \
    -e LOCAL_USER_ID="$(id -u)" \
    "${run_as_root_env[@]}" \
    -e GOCACHE=/go-cache \
    -e GOPATH=/go \
    -e KUBECONFIG=/kubeconfig \
    -e PRODUCT=${PRODUCT:-calico} \
    -e "E2E_PROCS=${E2E_PROCS:-4}" \
    -e K8S_E2E_FLAGS \
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
    bash -c 'export PATH=/go/src/github.com/projectcalico/calico/hack/test/kind:$PATH && \
      git config --global --add safe.directory "*" && \
      mkdir -p report && \
      go run github.com/onsi/ginkgo/v2/ginkgo -procs="${E2E_PROCS:-4}" \
        --junit-report=junit.xml --output-dir=report/ \
        ./e2e/bin/k8s/e2e.test -- ${K8S_E2E_FLAGS}' \
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
