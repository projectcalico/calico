#!/usr/bin/env bash
set -eo pipefail

echo "[INFO] starting global_epilogue"

cd "${BZ_HOME}"
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

if [[ "$SEMAPHORE_JOB_RESULT" != "passed" ]] || [[ "$TEST_TYPE" == "ocp-cert" ]]; then
  echo "[INFO] global_epilogue: capturing diags"
  bz diags $VERBOSE | tee ${BZ_LOGS_DIR}/diagnostic.log || true
  artifact push job ${BZ_LOCAL_DIR}/${DIAGS_ARCHIVE_FILENAME} --destination semaphore/diags.tgz || true
  if [[ "$GS_BUCKET" != "" ]]; then
    echo "[INFO] bucket_upload: capturing diags"
    gsutil cp ${BZ_LOCAL_DIR}/${DIAGS_ARCHIVE_FILENAME} gs://${GS_BUCKET}/${METADATA}/${DIAGS_ARCHIVE_FILENAME} || true
  fi
  rm -rf "${BZ_LOCAL_DIR:?}/${DIAGS_ARCHIVE_FILENAME:?}"
  rm -rf ${BZ_LOCAL_DIR}/diags
fi

echo "[INFO] global_epilogue: pushing report artifacts"
artifact push job ${REPORT_DIR} --destination semaphore/test-results || true
test-results publish ${REPORT_DIR}/junit.xml --name "$SEMAPHORE_JOB_NAME" || true
if [[ "$GS_BUCKET" != "" ]]; then
  echo "[INFO] bucket_upload: pushing report artifacts"
  gsutil cp ${REPORT_DIR}/junit.xml gs://${GS_BUCKET}/${METADATA}/junit.xml || true

  echo "[INFO] bucket_upload: pushing log artifacts"
  gsutil cp -r -z ${BZ_LOGS_DIR}/* gs://${GS_BUCKET}/${METADATA}/logs/ || true
fi

echo "[INFO] create and push test results to Lens"
echo "[INFO] downloading lens uploader script"
curl --retry 9 --retry-all-errors -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" \
     -H "Accept: application/vnd.github.v3.raw" \
     -o ./run-lens.sh \
      https://raw.githubusercontent.com/tigera/banzai-lens/main/uploader/run-lens.sh || true
echo "[INFO] running Lens Uploader"
chmod +x ./run-lens.sh || true
./run-lens.sh || true
cd "${BZ_HOME}"

echo "[INFO] global_epilogue: destroy"
bz destroy $VERBOSE | tee >(gzip --stdout > ${BZ_LOGS_DIR}/destroy.log.gz) || true
echo "[INFO] global_epilogue: pushing log artifacts"
artifact push job ${BZ_LOGS_DIR} --destination semaphore/logs || true

echo "[INFO] global_epilogue: deleting cache"
cache delete $SEMAPHORE_JOB_ID
