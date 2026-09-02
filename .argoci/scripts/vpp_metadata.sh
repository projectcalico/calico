#!/usr/bin/env bash
# Prints the gs:// prefix e2e-vpp publishes its own copy of results to, and
# nothing at all when this is not a scheduled run.
#
# The layout predates ArgoCI and the CalicoVPP maintainers have tooling built
# against it, so the shape here is deliberately theirs rather than ours.
set -euo pipefail

# One anchor shared by every step in the run. Calling date as each step exits
# would scatter a single run across sibling minute directories. Argo's random
# suffix is 5 characters, so a 10-digit field cannot be one -- and a run with no
# epoch is a PR run, which must not write into the bucket the maintainers read.
suffix="${ARGO_WORKFLOW_NAME:-}"
suffix="${suffix##*-}"
[[ "${suffix}" =~ ^[0-9]{10}$ ]] || exit 0

day=$(date -u -d "@${suffix}" +%Y-%m-%d)
hhmm=$(date -u -d "@${suffix}" +%H:%M)

flags=""
if [[ "${ENABLE_HUGEPAGES:-}"   == true            ]]; then flags+="/HUGEPAGES"; fi
if [[ "${ENABLE_VPP_IPSEC:-}"   == true            ]]; then flags+="/IPSEC";     fi
if [[ "${ENABLE_WIREGUARD:-}"   == true            ]]; then flags+="/WG";        fi
if [[ "${ENCAPSULATION_TYPE:-}" == VXLAN           ]]; then flags+="/VXLAN";     fi
if [[ "${DATAPLANE:-}"          == CalicoIptables  ]]; then flags+="/Iptables";  fi

# The empty ${VPP_MANIFEST_FILE} on the two OpenShift steps is what gives those
# paths the '//' they have always had. Reproduced on purpose.
printf 'gs://vpp-results/%s/%s/%s/%s%s/%s\n' \
  "${day}" "${RELEASE_STREAM}" "${PROVISIONER}" \
  "${VPP_MANIFEST_FILE:-}" "${flags}" "${hhmm}"
