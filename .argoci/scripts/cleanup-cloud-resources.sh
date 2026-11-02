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

  # gcloud warns on stderr when no instance carries the label yet, and that
  # warning parses as a leak.
  local listing errors
  errors=$(mktemp)
  if ! listing=$(gcloud --quiet compute instances list \
      --filter="labels.ci-system=${prefix} AND labels.ci-workflow-id=${CI_WORKFLOW_NAME}" \
      --format='csv[no-heading](name,zone.basename())' 2>"${errors}"); then
    echo "[WARN] could not list instances: $(cat "${errors}")"
    rm -f "${errors}"
    return 1
  fi
  rm -f "${errors}"
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
    [ -n "${name}" ] && [ -n "${zone}" ] || continue
    by_zone["${zone}"]+=" ${name}"
  done <<< "${listing}"

  local rc=0
  for zone in "${!by_zone[@]}"; do
    # shellcheck disable=SC2086 # deliberate word splitting: many names, one call
    if ! gcloud --quiet beta compute instances delete ${by_zone[$zone]} \
        --zone="${zone}" --no-graceful-shutdown; then
      still_there "compute instances" zone "${zone}" \
          --filter="labels.ci-system=${prefix} AND labels.ci-workflow-id=${CI_WORKFLOW_NAME}" || rc=1
    fi
  done
  return "${rc}"
}

# A lane's own teardown can delete what the sweep listed before the sweep gets to
# it, and gcloud then fails the whole delete for the missing ones. Fails only if
# something the listing matched is still in location.
still_there() {
  local kind=$1 scope=$2 location=$3
  shift 3
  local left
  # shellcheck disable=SC2086 # kind is several words
  if ! left=$(gcloud --quiet ${kind} list "$@" --format="csv[no-heading](name,${scope}.basename())" 2>/dev/null); then
    echo "[WARN] could not check what is left of ${kind} in ${location}"
    return 1
  fi
  left=$(awk -F, -v l="${location}" '$2 == l {print $1}' <<< "${left}")
  if [ -n "${left}" ]; then
    echo "[WARN] failed to delete ${kind} in ${location}: $(echo ${left})"
    return 1
  fi
  echo "[INFO] ${kind} in ${location} were already gone"
}

# bz labels nothing it creates, so a cluster is found by the name it recorded
# before provisioning, which every one of its resources starts with.
sweep_bz() {
  local dir
  dir=$(mktemp -d)
  if ! ( cd "${dir}" && artifact pull workflow bz-clusters ) >/dev/null 2>&1; then
    echo "[INFO] no bz clusters recorded"
    rm -rf "${dir}"
    return 0
  fi

  local rc=0 info CLUSTER_NAME GOOGLE_PROJECT
  for info in "${dir}"/bz-clusters/*.info; do
    [ -e "${info}" ] || continue
    CLUSTER_NAME="" GOOGLE_PROJECT=""
    # shellcheck disable=SC1090
    . "${info}"
    # Anything looser could match another run's cluster.
    if ! [[ "${CLUSTER_NAME}" =~ ^bz-[a-z0-9]+-[a-z0-9]{5}$ ]] || [ -z "${GOOGLE_PROJECT}" ]; then
      echo "[WARN] ignoring malformed record ${info##*/}"
      rc=1
      continue
    fi
    # Instances first: the instance group and the address are attached to them.
    delete_by_location "compute instances" zone "${GOOGLE_PROJECT}" "name~^${CLUSTER_NAME}-" || rc=1
    delete_by_location "compute instance-groups unmanaged" zone "${GOOGLE_PROJECT}" "name~^${CLUSTER_NAME}-" || rc=1
    delete_by_location "compute addresses" region "${GOOGLE_PROJECT}" "name~^${CLUSTER_NAME}-" || rc=1
    delete_global "compute firewall-rules" "${GOOGLE_PROJECT}" "name~^${CLUSTER_NAME}-" || rc=1
  done
  rm -rf "${dir}"
  return "${rc}"
}

# gcloud takes many names per delete but only one zone or region.
delete_by_location() {
  local kind=$1 scope=$2 project=$3 filter=$4 listing name loc rc=0
  # shellcheck disable=SC2086 # kind is several words
  if ! listing=$(gcloud --quiet ${kind} list --project "${project}" --filter="${filter}" \
      --format="csv[no-heading](name,${scope}.basename())" 2>/dev/null); then
    echo "[WARN] could not list ${kind} matching ${filter}"
    return 1
  fi
  [ -n "${listing}" ] || return 0
  echo "[WARN] ${kind} outlived their cluster:"
  echo "${listing}"

  local -A by_loc=()
  while IFS=, read -r name loc; do
    [ -n "${name}" ] && [ -n "${loc}" ] || continue
    by_loc["${loc}"]+=" ${name}"
  done <<< "${listing}"
  for loc in "${!by_loc[@]}"; do
    # shellcheck disable=SC2086 # deliberate word splitting: many names, one call
    if ! gcloud --quiet ${kind} delete ${by_loc[$loc]} --project "${project}" --"${scope}"="${loc}"; then
      still_there "${kind}" "${scope}" "${loc}" --project "${project}" --filter="${filter}" || rc=1
    fi
  done
  return "${rc}"
}

delete_global() {
  local kind=$1 project=$2 filter=$3 names
  # shellcheck disable=SC2086 # kind is several words
  if ! names=$(gcloud --quiet ${kind} list --project "${project}" --filter="${filter}" \
      --format='value(name)' 2>/dev/null); then
    echo "[WARN] could not list ${kind} matching ${filter}"
    return 1
  fi
  [ -n "${names}" ] || return 0
  echo "[WARN] ${kind} outlived their cluster: $(echo ${names})"
  # shellcheck disable=SC2086
  gcloud --quiet ${kind} delete ${names} --project "${project}"
}

# One resource group per Windows lane, each named from the run.
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

  if [ -z "${CI_WORKFLOW_NAME:-}" ]; then
    echo "[INFO] no workflow name; skipping the resource group sweep"
    return 0
  fi
  local rc=0 rg
  for rg in \
      "${prefix}-win-felix-${CI_WORKFLOW_NAME}-rg" \
      "${prefix}-win-cni-${CI_WORKFLOW_NAME}-overlay-rg" \
      "${prefix}-win-cni-${CI_WORKFLOW_NAME}-l2bridge-rg"; do
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
sweep_bz || status=1
sweep_azure || status=1
exit "${status}"
