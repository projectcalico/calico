#!/usr/bin/env bash
# run_tests.sh - acquire an e2e binary and run it, or defer to bz tests.
#
# Selection (automatic, matches Semaphore):
#   - TEST_TYPE == k8s-e2e → run the monorepo e2e binary via `make e2e-run`.
#     The binary is acquired first: built from local source when RUN_LOCAL_TESTS
#     is set (per-PR CI), otherwise downloaded from the hashrelease (scheduled
#     CI). E2E_TEST_CONFIG selects specs; when it is empty, the legacy
#     K8S_E2E_FLAGS regexes are used instead.
#   - Else (non-e2e test types: benchmarks, certification, etc.) → `bz tests`.
#
# Required env:
#   BZ_LOCAL_DIR, BZ_LOGS_DIR, HOME, REPORT_DIR, TEST_TYPE
# Required for local builds:
#   E2E_TEST_CONFIG or K8S_E2E_FLAGS
# Required for hashrelease downloads:
#   RELEASE_STREAM
#
# Sourced from body_*.sh. Exits with the test exit code.

for _var in BZ_LOCAL_DIR BZ_LOGS_DIR HOME REPORT_DIR TEST_TYPE; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

# check_component_logs - publish stern's verdict on the Calico component logs.
#
# `bz tests` used to do this; the direct-ginkgo path above bypasses it, so the
# check has been deployed-but-unread on OSS lanes since the switch. Everything
# here is advisory: errexit is on and the checker exits non-zero by design, so
# each fallible command is `rc=0; cmd || rc=$?` and the function always
# returns 0. The test exit code is never touched.
check_component_logs() {
  local mode rc scripts stern_scripts stern_log check_out check_err kube_err
  local stern_xml merge_dir

  mode="$(echo "${STERN_CHECK:-ERROR}" | tr '[:lower:]' '[:upper:]')"
  [[ "${mode}" == "DISABLED" ]] && return 0
  if [[ "${mode}" != "ERROR" && "${mode}" != "INFO" ]]; then
    echo "[WARN] unrecognised STERN_CHECK=${mode}; treating as ERROR"
    mode=ERROR
  fi

  local _v
  for _v in BZ_HOME BZ_LOCAL_DIR BZ_LOGS_DIR REPORT_DIR RUN_IMAGE; do
    if [[ -z "${!_v:-}" ]]; then
      echo "[WARN] component-log check skipped: ${_v} is not set"
      return 0
    fi
  done

  scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  stern_scripts="${BZ_HOME}/dependencies/stern/scripts"
  stern_log="${BZ_LOGS_DIR}/stern.log"
  check_out="${BZ_LOGS_DIR}/stern-check.out"
  check_err="${BZ_LOGS_DIR}/stern-check.err"
  kube_err="${BZ_LOGS_DIR}/stern-kubectl.err"
  stern_xml="${BZ_LOCAL_DIR}/junit-stern.xml"

  if [[ ! -d "${stern_scripts}" ]]; then
    echo "[WARN] component-log check skipped: ${stern_scripts} not found"
    return 0
  fi

  # --tail=-1 is required: with --selector, kubectl defaults to --tail=10.
  # KUBECONFIG is required: it is only ever set as container env for the e2e
  # run, never exported for the host shell.
  rc=0
  KUBECONFIG="${BZ_LOCAL_DIR}/kubeconfig" timeout 120 "${BZ_LOCAL_DIR}/bin/kubectl" \
    logs --selector app=stern -n stern --tail=-1 \
    > "${stern_log}" 2> "${kube_err}" || rc=$?
  if [[ ${rc} -ne 0 ]]; then
    echo "[WARN] component-log check skipped: could not read stern logs (rc=${rc})"
    tail -n 20 "${kube_err}" 2>/dev/null || true
    return 0
  fi

  # Read the filter config from where banzai-core rendered it, so the
  # include/exclude lists stay single-sourced (and pick up STERN_EXCLUDES).
  rc=0
  STERN_CONFIG="$("${BZ_LOCAL_DIR}/bin/yq" r "${BZ_HOME}/Taskvars.yml" STERN_CONFIG 2>/dev/null)" || rc=$?
  if [[ ${rc} -ne 0 || -z "${STERN_CONFIG}" ]]; then
    echo "[WARN] component-log check skipped: STERN_CONFIG not readable from Taskvars.yml"
    return 0
  fi
  # docker -e STERN_CONFIG forwards from the environment; unexported sends
  # nothing and log_checker would fatal on an empty config.
  export STERN_CONFIG

  # Run in the e2e image rather than on the host: the lanes have no Go, and
  # installing one costs an ~80MB fetch from a host outside the CI proxy. The
  # image runs as a non-root UID against a read-only mount, hence the writable
  # GOCACHE/HOME and -w /tmp.
  rc=0
  timeout 300 docker run --rm \
    -e STERN_CONFIG -e GOCACHE=/tmp/go-cache -e HOME=/tmp \
    -v "${stern_scripts}:/scripts:ro" \
    -v "${stern_log}:/stern.log:ro" \
    -w /tmp "${RUN_IMAGE}" \
    go run /scripts/log_checker.go /stern.log \
    > "${check_out}" 2> "${check_err}" || rc=$?

  if [[ ${rc} -eq 124 ]]; then
    echo "[WARN] component-log check timed out; not treating as a failure"
    return 0
  fi

  if [[ ${rc} -eq 0 ]]; then
    echo "[INFO] Calico component logs all clear"
    # Publish a passing case too: absence of this testcase is then a signal that
    # the check itself has broken, which is how it went unnoticed last time.
    rc=0
    python3 "${scripts}/stern_junit.py" --pass "${check_out}" "${stern_xml}" || rc=$?
  else
    echo "[ERROR] Found Calico component log ERRORs in stern log"
    rc=0
    python3 "${scripts}/stern_junit.py" "${check_out}" "${stern_xml}" || rc=$?
    if [[ ${rc} -eq 2 ]]; then
      # log_checker exits 1 for log.Fatalf as well as for a genuine hit.
      echo "[WARN] component-log check produced no parseable output; ignoring"
      tail -n 20 "${check_err}" 2>/dev/null || true
      return 0
    fi
  fi
  if [[ ${rc} -ne 0 ]]; then
    echo "[WARN] component-log check: could not build JUnit report"
    return 0
  fi

  [[ "${mode}" == "INFO" ]] && return 0

  if [[ ! -f "${REPORT_DIR}/junit.xml" ]]; then
    # ginkgo produced nothing; leave ours for the epilogue's own merge, which
    # runs precisely when junit.xml is absent.
    cp "${stern_xml}" "${REPORT_DIR}/junit-stern.xml" || true
    return 0
  fi

  # Merge from a directory holding only these two documents: merge_junit.py
  # recursively absorbs every *.xml it is pointed at, and REPORT_DIR is not ours
  # alone. It also skips its own output, so that must be a separate path.
  merge_dir="$(mktemp -d)" || return 0
  if cp "${stern_xml}" "${merge_dir}/junit-stern.xml" \
     && cp "${REPORT_DIR}/junit.xml" "${merge_dir}/junit-e2e.xml" \
     && python3 "${scripts}/merge_junit.py" "${merge_dir}" "${merge_dir}/merged.xml" \
     && python3 "${scripts}/stern_junit.py" --verify "${merge_dir}/merged.xml" "${REPORT_DIR}/junit.xml"; then
    cp "${merge_dir}/merged.xml" "${REPORT_DIR}/junit.xml" || true
  else
    echo "[WARN] stern result not merged; junit.xml left as-is"
  fi
  rm -rf "${merge_dir}" || true
  return 0
}

if [[ -n "${RUN_LOCAL_TESTS:-}" ]]; then
  # Per-PR CI: build the e2e binary from the local source tree.
  echo "[INFO] building e2e binary from local source..."
  pushd "${CI_HOME}/${CI_GIT_DIR}" || exit
  make -C e2e build |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/${TEST_TYPE}-build.log.gz")
  E2E_BINARY=/go/src/github.com/projectcalico/calico/e2e/bin/k8s/e2e.test
  popd || exit
elif [[ "${TEST_TYPE}" == "k8s-e2e" ]]; then
  # Scheduled CI: download the pre-built e2e binary from the hashrelease.
  echo "[INFO] downloading e2e binary from hashrelease..."
  # Upgrade runs set RELEASE_STREAM to the downlevel version they install
  # first, but the tests run against the uplevel version.
  E2E_STREAM=${UPLEVEL_RELEASE_STREAM:-${RELEASE_STREAM}}
  HASHREL_URL=$(curl --retry 9 --retry-all-errors -fsS "https://latest-os.hashrelease.tools.tigera.net/${E2E_STREAM}.txt")
  echo "[INFO] hashrelease URL: ${HASHREL_URL}"
  ARCH=$(uname -m); [[ "$ARCH" == "x86_64" ]] && ARCH=amd64; [[ "$ARCH" == "aarch64" ]] && ARCH=arm64
  mkdir -p "${CI_HOME}/${CI_GIT_DIR}/e2e/bin/k8s"
  curl --retry 9 --retry-all-errors -fsSL "${HASHREL_URL}/files/e2e/e2e-linux-${ARCH}.test" -o "${CI_HOME}/${CI_GIT_DIR}/e2e/bin/k8s/e2e.test"
  chmod +x "${CI_HOME}/${CI_GIT_DIR}/e2e/bin/k8s/e2e.test"
  echo "[INFO] downloaded e2e binary to ${CI_HOME}/${CI_GIT_DIR}/e2e/bin/k8s/e2e.test"
  E2E_BINARY=/go/src/github.com/projectcalico/calico/e2e/bin/k8s/e2e.test
fi

# E2E_BINARY is a set/unset sentinel (its value is not used here -- make
# e2e-run locates the binary itself). Take the structured path whenever a
# k8s-e2e binary was acquired above; non-e2e test types fall through to bz
# tests below.
if [[ -n "${E2E_BINARY:-}" ]]; then
  echo "[INFO] starting e2e tests..."

  # Pick one selection channel: an empty config runs the whole suite unfiltered.
  if [[ -n "${E2E_TEST_CONFIG:-}" ]]; then
    E2E_GINKGO_ARGS=""
  elif [[ -n "${K8S_E2E_FLAGS:-}" ]]; then
    E2E_GINKGO_ARGS="${K8S_E2E_FLAGS}"
  else
    echo "[ERROR] neither E2E_TEST_CONFIG nor K8S_E2E_FLAGS is set; refusing to run the whole suite"
    exit 1
  fi

  pushd "${CI_HOME}/${CI_GIT_DIR}" || exit

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

  # EKS kubeconfigs exec aws-iam-authenticator (PATH lookup), which the stock
  # golang image lacks, so client-go fails before any tests run. The aws-eks
  # provisioner installs it on the host; bind-mount it when present (no-op otherwise).
  # It also needs AWS creds in the container (else it exits 1 and
  # SynchronizedBeforeSuite fails). Mount ~/.aws (written by the prologue) and point
  # the SDK at it via env -- container runs as an arbitrary UID.
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

  # The go-build entrypoint useradds LOCAL_USER_ID and su-execs to that account,
  # which cannot work when the runner is already root. RUN_AS_ROOT skips it.
  run_as_root_env=()
  if [[ "$(id -u)" -eq 0 ]]; then
    run_as_root_env=(-e RUN_AS_ROOT=true)
  fi

  # Resolve the Go build cache the way lib.Makefile does, so the host-side
  # `make -C e2e build` above and this container share one cache rather than
  # compiling from cold in each: LOCAL_GO_PKG_CACHE, then GOCACHE when the Go
  # tools resolve it to an absolute path, then the repo-local default.
  go_cache="${LOCAL_GO_PKG_CACHE:-$(go env GOCACHE 2>/dev/null || true)}"
  case "${go_cache}" in
    /*) ;;
    *) go_cache="$(pwd)/.go-pkg-cache" ;;
  esac
  mkdir -p "${go_cache}"

  # Capture the exit code so the JUnit copy below runs even when tests fail
  # (set -e would otherwise bail out before the cp).
  e2e_rc=0
  docker run --rm --init --net=host \
    -e LOCAL_USER_ID="$(id -u)" \
    "${run_as_root_env[@]}" \
    -e GOCACHE=/go-cache \
    -e GOPATH=/go \
    -e KUBECONFIG=/kubeconfig \
    -e PRODUCT=${PRODUCT:-calico} \
    -e E2E_GINKGO_ARGS="${E2E_GINKGO_ARGS}" \
    -e WINDOWS_OS \
    ${K8S_E2E_DOCKER_EXTRA_FLAGS:-} \
    "${auth_mount[@]}" \
    "${aws_cred_env[@]}" \
    -v "$(pwd)":/go/src/github.com/projectcalico/calico:rw \
    -v "${go_cache}":/go-cache:rw \
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

  check_component_logs

  # Propagate the original test exit code.
  exit ${e2e_rc}
else
  # Non-e2e test types (benchmarks, certification, etc.) -- defer to bz.
  echo "[INFO] starting bz testing (K8S_E2E_FLAGS=${K8S_E2E_FLAGS:-<none>})..."
  bz tests ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log.gz")
fi
