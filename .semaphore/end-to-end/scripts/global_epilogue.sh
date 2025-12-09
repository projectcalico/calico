#!/usr/bin/env bash
set -eo pipefail

delete_artifacts() {
  echo "[INFO] Deleting artifacts that are already pushed"
  sudo rm -rf ${BZ_LOCAL_DIR}/${DIAGS_ARCHIVE_FILENAME} || true
  sudo rm -rf ${BZ_LOCAL_DIR}/diags || true
  sudo rm -rf ~/.cache/* /var/lib/apt/lists/* || true
}

delete_calicoctl() {
  echo "[INFO] Deleting calicoctl"
  sudo rm -rf ${BZ_LOGS_DIR}/bin/kubectl-calico || true
  sudo rm -rf ${BZ_LOGS_DIR}/bin/calico-* || true
}

delete_gcloud() {
  if [[ ! $PROVISIONER =~ ^gcp-.* ]]; then
    sudo NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=a apt remove google-cloud-cli google-cloud-cli-gke-gcloud-auth-plugin -y && sudo needrestart -r a || true
  fi
}

echo "[INFO] starting global_epilogue"


if [[ "${BZ_VERBOSE}" == "true" ]]; then
  VERBOSE="--verbose"
else
  VERBOSE=""
fi

# If we've got GS_BUCKET defined, we should upload results and logs to Google Storage too.  This is used by the VPP pipelines.
if [[ "$GS_BUCKET" != "" ]]; then
  # Assemble metadata prefix for run artifacts
  METADATA="$(date -d @${SEMAPHORE_PIPELINE_STARTED_AT} -u --iso-8601=d)/${RELEASE_STREAM}/${PROVISIONER}/${MANIFEST_FILE}"
  if [[ "${ENABLE_HUGEPAGES}" == "true" ]]; then
    METADATA=${METADATA}/HUGEPAGES
  fi
  if [[ "${ENABLE_VPP_IPSEC}" == "true" ]]; then
    METADATA=${METADATA}/IPSEC
  fi
  if [[ "${ENABLE_WIREGUARD}" == "true" ]]; then
    METADATA=${METADATA}/WG
  fi
  if [[ "${DATAPLANE}" == "CalicoIptables" ]]; then
    METADATA=${METADATA}/Iptables
  fi
  METADATA=${METADATA}/$(date -d @${SEMAPHORE_PIPELINE_STARTED_AT} -u +%H:%M)
fi


if [[ ${HCP_STAGE:-} != *-hosting* ]]; then
  echo "[INFO] create report and push test results to Lens"
  cd ./scripts
  echo "[INFO] downloading lens uploader script"
  curl -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" \
      -H "Accept: application/vnd.github.v3.raw" \
      -o ./run-lens.sh \
        https://raw.githubusercontent.com/tigera/banzai-lens/main/uploader/run-lens.sh || true
  echo "[INFO] running Lens uploader script"
  chmod +x ./run-lens.sh || true
  ./run-lens.sh || true
  docker system prune -f || true
fi

echo "[INFO] BZ_HOME=${BZ_HOME}"
cd "${BZ_HOME}"

if [[ "${HCP_ENABLED}" == "true" ]]; then
  # if test isn't passed OR if test_type is ocp-certification, capture diags
  if [[ "$SEMAPHORE_JOB_RESULT" != "passed" || "$TEST_TYPE" == "ocp-cert" ]]; then
    echo "[INFO] global_epilogue: hcp: capturing diags"
    hcp-diags.sh |& tee ${BZ_LOGS_DIR}/diagnostic.log || true
    artifact push job ${BZ_PROFILES_PATH}/.diags --destination semaphore/diags || true
  fi

  echo "[INFO] global_epilogue: hcp: pushing report artifacts"
  artifact push job ${BZ_PROFILES_PATH}/.report --destination semaphore/test-results || true

  echo "[INFO] publish new semaphore test results"
  test-results publish semaphore/test-results/junit.xml || true

  delete_artifacts; delete_calicoctl; delete_gcloud

  echo "[INFO] global_epilogue: hcp destroy"
  hcp-destroy.sh |& tee ${BZ_LOGS_DIR}/destroy.log || true

  echo "[INFO] global_epilogue: hcp: pushing log artifacts"
  artifact push job ${BZ_LOGS_DIR} --destination semaphore/logs || true
else
  if [[ ${HCP_STAGE:-} != *?-hosting* ]]; then

    if [[ "$SEMAPHORE_JOB_RESULT" != "passed" || "$TEST_TYPE" == "ocp-cert" ]]; then
      echo "[INFO] global_epilogue: capturing diags"
      bz diags $VERBOSE |& tee ${BZ_LOGS_DIR}/diagnostic.log || true
      artifact push job ${BZ_LOCAL_DIR}/${DIAGS_ARCHIVE_FILENAME} --destination semaphore/diags.tgz || true
      if [[ "$GS_BUCKET" != "" ]]; then
        echo "[INFO] bucket_upload: capturing diags"
        gsutil cp ${BZ_LOCAL_DIR}/${DIAGS_ARCHIVE_FILENAME} gs://${GS_BUCKET}/${METADATA}/${DIAGS_ARCHIVE_FILENAME} || true
      fi
    fi

    delete_artifacts; delete_calicoctl; delete_gcloud

    REPORT_DIR=${REPORT_DIR:-"${BZ_LOCAL_DIR}/report/${TEST_TYPE}"}
    echo "[INFO] global_epilogue: pushing report artifacts"
    artifact push job ${REPORT_DIR} --destination semaphore/test-results || true
    cp ${REPORT_DIR}/junit.xml . || true

    echo "[INFO] publish new semaphore test results"
    test_publish=0
    test-results publish ${REPORT_DIR}/junit.xml --name "$SEMAPHORE_JOB_NAME" || test_publish=1
    echo "[INFO] Status of Publishing test results to Semaphore: ${test_publish}"
  fi

  if [[ "${HCP_STAGE}" == "setup-hosting" ]]; then
    artifact push workflow ${BZ_LOCAL_DIR}/kubeconfig -f --destination hosting-${HOSTING_CLUSTER}-kubeconfig
  elif [[ "${HCP_STAGE}" != "hosting" ]]; then
    echo "[INFO] global_epilogue: destroy"
    bz destroy $VERBOSE |& tee ${BZ_LOGS_DIR}/destroy.log || true
  fi
  echo "[INFO] global_epilogue: pushing log artifacts"
  artifact push job ${BZ_LOGS_DIR} --destination semaphore/logs || true
fi

echo "[INFO] global_epilogue: deleting cache"

if [[ "${HCP_STAGE}" == "destroy-hosting" ]]; then
  artifact yank workflow hosting-${HOSTING_CLUSTER}-kubeconfig
  cache delete ${SEMAPHORE_WORKFLOW_ID}-hosting-${HOSTING_CLUSTER}
  cache delete $(basename $PWD)
elif [[ "${HCP_STAGE}" == "hosting" ]]; then
  :
elif [[ "${HCP_STAGE}" != "setup-hosting" ]]; then
  cache delete ${SEMAPHORE_JOB_ID}
fi
