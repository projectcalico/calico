#!/usr/bin/env bash

# run_tests.sh - acquire an e2e binary and run it, or defer to bz tests.

# Three modes: RUN_LOCAL_TESTS builds from local source, TEST_TYPE k8s-e2e
# downloads from the hashrelease, anything else defers to bz tests.
# E2E_TEST_CONFIG names the YAML config that selects the specs.

# Required env: BZ_LOCAL_DIR, BZ_LOGS_DIR, HOME, REPORT_DIR, TEST_TYPE.
# The e2e path also needs E2E_TEST_CONFIG, plus RELEASE_STREAM to find a binary.

# Sourced from body_*.sh. Exits with the test exit code.

for _var in BZ_LOCAL_DIR BZ_LOGS_DIR HOME REPORT_DIR TEST_TYPE; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

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
  HASHREL_URL=$(curl --retry 9 --retry-all-errors -fsS "https://latest-os.hashrelease.tools.tigera.net/${RELEASE_STREAM}.txt")
  echo "[INFO] hashrelease URL: ${HASHREL_URL}"
  ARCH=$(uname -m); [[ "$ARCH" == "x86_64" ]] && ARCH=amd64; [[ "$ARCH" == "aarch64" ]] && ARCH=arm64
  mkdir -p "${CI_HOME}/${CI_GIT_DIR}/e2e/bin/k8s"
  curl --retry 9 --retry-all-errors -fsSL "${HASHREL_URL}/files/e2e/e2e-linux-${ARCH}.test" -o "${CI_HOME}/${CI_GIT_DIR}/e2e/bin/k8s/e2e.test"

  # A 200 carrying an error page would otherwise be chmod +x'd and only fail much
  # later, inside ginkgo, as an exec-format error.
  if [[ "$(stat -c %s "${CI_HOME}/${CI_GIT_DIR}/e2e/bin/k8s/e2e.test" 2>/dev/null || echo 0)" -lt 10000000 ]]; then
    echo "[ERROR] downloaded e2e binary is implausibly small; the pointer is probably wrong"
    exit 1
  fi
  chmod +x "${CI_HOME}/${CI_GIT_DIR}/e2e/bin/k8s/e2e.test"
  echo "[INFO] downloaded e2e binary to ${CI_HOME}/${CI_GIT_DIR}/e2e/bin/k8s/e2e.test"
  E2E_BINARY=/go/src/github.com/projectcalico/calico/e2e/bin/k8s/e2e.test
fi

# E2E_BINARY is a set/unset sentinel; make e2e-run locates the binary itself.
# Non-e2e test types acquire none and fall through to bz tests.
if [[ -n "${E2E_BINARY:-}" ]]; then
  echo "[INFO] starting e2e tests..."

  if [[ -z "${E2E_TEST_CONFIG:-}" ]]; then
    echo "[ERROR] E2E_TEST_CONFIG is not set; refusing to run the whole suite"
    exit 1
  fi

  pushd "${CI_HOME}/${CI_GIT_DIR}" || exit

  # The local-build path already pulled calico/go-build, so reuse it. The
  # hashrelease path compiled nothing, so use the smaller golang image and
  # install what the CGO-linked binary needs at runtime.
  PRE_RUN=":"
  if [[ -n "${RUN_LOCAL_TESTS:-}" ]]; then
    GO_BUILD_VER=$(make --no-print-directory -f ./metadata.mk -f - <<<'print:; @echo $(GO_BUILD_VER)' print)
    RUN_IMAGE="calico/go-build:${GO_BUILD_VER}"
  else
    GO_VERSION=$(make --no-print-directory -f ./metadata.mk -f - <<<'print:; @echo $(GO_VERSION)' print)
    RUN_IMAGE="golang:${GO_VERSION}-bookworm"
    PRE_RUN="apt-get update -qq && apt-get install -y --no-install-recommends libelf1 zlib1g uuid-runtime"
  fi

  # The upstream framework shells out to kubectl for every exec-into-pod step,
  # so a K8S_VERSION-pinned binary has to be on PATH inside the runner.
  make kubectl

  # A managed kubeconfig execs a credential plugin by name: aws-iam-authenticator
  # on EKS, gke-gcloud-auth-plugin on GKE, kubelogin on AKS. bz provisions all of
  # them into BZ_LOCAL_DIR/bin, so mount that and put it on PATH.
  auth_mount=()
  if [[ -d "${BZ_LOCAL_DIR}/bin" ]]; then
    auth_mount=(-v "${BZ_LOCAL_DIR}/bin:/bz-bin:ro")
  fi

  # Those plugins read the cloud credentials the prologue staged under HOME.
  for _dir in .aws .azure .config/gcloud; do
    if [[ -d "${HOME}/${_dir}" ]]; then
      auth_mount+=(-v "${HOME}/${_dir}:/cloud/${_dir}:ro")
    fi
  done
  if [[ -f "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
    auth_mount+=(-v "${GOOGLE_APPLICATION_CREDENTIALS}:/cloud/gcp-key.json:ro"
                 -e GOOGLE_APPLICATION_CREDENTIALS=/cloud/gcp-key.json)
  fi

  # aws-iam-authenticator exits 1 without credentials, which fails the suite in
  # SynchronizedBeforeSuite. The container runs as an arbitrary UID, so point the
  # SDK at the mount rather than relying on HOME.
  aws_cred_env=()
  if [[ -d "${HOME}/.aws" ]]; then
    aws_cred_env=(-e AWS_SHARED_CREDENTIALS_FILE=/cloud/.aws/credentials
                  -e AWS_CONFIG_FILE=/cloud/.aws/config
                  -e "AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}")
  fi

  # Config the specs read from the environment. Named rather than valued so a
  # lane that sets none forwards none.
  spec_env=()
  for _var in NON_CLUSTER_HOSTS_YAML REMOTE_KUBECONFIG LOG_LEVEL \
              KUBEVIRT_TEST_VM_IMAGE IPAM_TEST_POOL_SUBNET; do
    if [[ -n "${!_var:-}" ]]; then spec_env+=(-e "${_var}"); fi
  done

  # Hand the module download and the apt-get inside PRE_RUN the same proxy the
  # host uses, where a lane runs behind one.
  proxy_env=()
  for _var in HTTP_PROXY HTTPS_PROXY NO_PROXY GOPROXY; do
    if [[ -n "${!_var:-}" ]]; then proxy_env+=(-e "${_var}"); fi
  done

  # OpenShift taints its control-plane nodes NoSchedule, and the framework waits
  # for every node to be schedulable, so untaint them the way bz tests did.
  for _taint in node-role.kubernetes.io/master- node-role.kubernetes.io/control-plane-; do
    KUBECONFIG="${BZ_LOCAL_DIR}/kubeconfig" ./hack/test/kind/kubectl taint nodes --all "${_taint}" || true
  done

  # Private clusters reach the API only through a SOCKS tunnel that banzai-core
  # persists to Taskvars.yml. Empty and a no-op on a public cluster.
  TUNNEL_CMD="$(grep -E '^MASTER_TUNNEL_COMMAND:' "$(dirname "${BZ_LOCAL_DIR}")/Taskvars.yml" 2>/dev/null | sed -E 's/^MASTER_TUNNEL_COMMAND:[[:space:]]*//' || true)"

  # The command is a foreground `ssh -qN`, so the backgrounded job is ssh itself
  # and $! is the PID to kill. Only tear down a tunnel this script started.
  TUNNEL_PID=""
  if [[ -n "${TUNNEL_CMD}" ]] && ! pgrep -fx "${TUNNEL_CMD}" >/dev/null 2>&1; then
    echo "[INFO] opening SOCKS tunnel for private-cluster API access"
    ${TUNNEL_CMD} &
    TUNNEL_PID=$!
  fi

  # The go-build entrypoint useradds LOCAL_USER_ID and su-execs to that account,
  # which cannot work when the runner is already root. RUN_AS_ROOT skips it.
  run_as_root_env=()
  if [[ "$(id -u)" -eq 0 ]]; then
    run_as_root_env=(-e RUN_AS_ROOT=true)
  fi

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
    ${K8S_E2E_DOCKER_EXTRA_FLAGS:-} \
    ${auth_mount[@]+"${auth_mount[@]}"} \
    ${aws_cred_env[@]+"${aws_cred_env[@]}"} \
    ${spec_env[@]+"${spec_env[@]}"} \
    ${proxy_env[@]+"${proxy_env[@]}"} \
    -v "$(pwd)":/go/src/github.com/projectcalico/calico:rw \
    -v "$(pwd)"/.go-pkg-cache:/go-cache:rw \
    -v "${BZ_LOCAL_DIR}/kubeconfig:/kubeconfig:ro" \
    -w /go/src/github.com/projectcalico/calico \
    "${RUN_IMAGE}" \
    bash -c "${PRE_RUN} && \
      export PATH=/bz-bin:/go/src/github.com/projectcalico/calico/hack/test/kind:\$PATH && \
      git config --global --add safe.directory '*' && \
      make e2e-run \
        KUBECONFIG=/kubeconfig \
        E2E_TEST_CONFIG='${E2E_TEST_CONFIG}' \
        E2E_OUTPUT_DIR=report \
        E2E_JUNIT_REPORT=junit.xml" \
    |& tee "${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log" || e2e_rc=$?

  # Close the SOCKS tunnel only if we opened it (no-op otherwise).
  [[ -n "${TUNNEL_PID}" ]] && kill "${TUNNEL_PID}" >/dev/null 2>&1 || true

  mkdir -p "${REPORT_DIR}"
  if [[ -f report/junit.xml ]]; then
    cp report/junit.xml "${REPORT_DIR}/junit.xml"
    cp report/report.json "${REPORT_DIR}/report.json" 2>/dev/null || true
  else
    echo "[ERROR] no report/junit.xml was produced (rc=${e2e_rc}); the run did not reach ginkgo"
    if [[ "${e2e_rc}" -eq 0 ]]; then e2e_rc=1; fi
  fi
  popd || exit

  # Propagate the original test exit code.
  exit ${e2e_rc}
else
  # Non-e2e test types (benchmarks, certification) defer to bz.
  echo "[INFO] starting bz testing..."
  bz tests ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log.gz")
fi
