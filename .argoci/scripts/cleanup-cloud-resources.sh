#!/bin/bash
# Deletes cloud resources a run's lanes created but never tore down, such as
# after a pod was killed before its epilogue.
#
# Scoped by label and name prefix, since other CI systems share the project and
# subscription.

set -u

prefix="${ARGOCI_RESOURCE_PREFIX:?the workflow must define it}"

status=0

sweep_gce() {
  if [ -z "${CI_WORKFLOW_NAME:-}" ]; then
    echo "[INFO] no workflow name; skipping the instance sweep"
    return 0
  fi

  local listing
  if ! listing=$(gcloud --quiet compute instances list \
      --filter="labels.ci-system=${prefix} AND labels.ci-workflow-id=${CI_WORKFLOW_NAME}" \
      --format='csv[no-heading](name,zone.basename())' 2>&1); then
    echo "[WARN] could not list instances: ${listing}"
    return 1
  fi
  if [ -z "${listing}" ]; then
    echo "[INFO] no leaked instances for ${CI_WORKFLOW_NAME}"
    return 0
  fi

  echo "[WARN] instances outlived their lane:"
  echo "${listing}"

  # gcloud takes many names per call but only one zone, and the fleet spreads
  # itself across a region's zones.
  local -A by_zone=()
  local name zone
  while IFS=, read -r name zone; do
    [ -n "${name}" ] || continue
    by_zone["${zone}"]+=" ${name}"
  done <<< "${listing}"

  local rc=0
  for zone in "${!by_zone[@]}"; do
    # shellcheck disable=SC2086 # deliberate word splitting: many names, one call
    if ! gcloud --quiet beta compute instances delete ${by_zone[$zone]} \
        --zone="${zone}" --no-graceful-shutdown; then
      echo "[WARN] failed to delete one or more instances in ${zone}"
      rc=1
    fi
  done
  return "${rc}"
}

# One resource group per Windows lane, each named from the commit under test.
sweep_azure() {
  if [ -z "${AZ_SP_ID:-}" ]; then
    echo "[INFO] no Azure credentials; skipping the resource group sweep"
    return 0
  fi
  if ! az login --service-principal -u "${AZ_SP_ID}" -p "${AZ_SP_PASSWORD}" \
      --tenant "${AZ_TENANT_ID}" --output none; then
    echo "[WARN] could not log in to Azure; leaving any groups in place"
    return 1
  fi

  local sha=${CI_GIT_SHA:0:4}
  local pr=${CI_GIT_PR_NUMBER:-merge}
  local rc=0 rg
  for rg in \
      "${prefix}-win-felix-${sha}-pr${pr}-rg" \
      "${prefix}-win-cni-${sha}-pr${pr}-overlay-rg" \
      "${prefix}-win-cni-${sha}-pr${pr}-l2bridge-rg"; do
    if ! az group show --name "${rg}" >/dev/null 2>&1; then
      continue
    fi
    echo "[WARN] resource group ${rg} outlived its lane; deleting"
    # Azure takes minutes to finish, and nothing here waits on it.
    if ! az group delete --name "${rg}" --yes --no-wait; then
      echo "[WARN] failed to start deletion of ${rg}"
      rc=1
    fi
  done
  return "${rc}"
}

sweep_gce || status=1
sweep_azure || status=1
exit "${status}"
