#!/bin/bash

set -eu

source $(cd $(dirname $0) && pwd)/helpers.sh

CWD=$(pwd)
LIBBPF_PATH=$(pwd)
REPO_PATH=$1

BPF_NEXT_ORIGIN=https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git
LINUX_SHA=$(cat ${LIBBPF_PATH}/CHECKPOINT-COMMIT)
SNAPSHOT_URL=https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/snapshot/bpf-next-${LINUX_SHA}.tar.gz

echo REPO_PATH = ${REPO_PATH}
echo LINUX_SHA = ${LINUX_SHA}

if [ ! -d "${REPO_PATH}" ]; then
	echo
	travis_fold start pull_kernel_srcs "Fetching kernel sources"

	mkdir -p $(dirname "${REPO_PATH}")
	cd $(dirname "${REPO_PATH}")
	# attempt to fetch desired bpf-next repo snapshot
	if wget ${SNAPSHOT_URL} && tar xf bpf-next-${LINUX_SHA}.tar.gz ; then
		mv bpf-next-${LINUX_SHA} $(basename ${REPO_PATH})
	else
		# but fallback to git fetch approach if that fails
		mkdir -p $(basename ${REPO_PATH})
		cd $(basename ${REPO_PATH})
		git init
		git remote add bpf-next ${BPF_NEXT_ORIGIN}
		# try shallow clone first
		git fetch --depth 32 bpf-next
		# check if desired SHA exists
		if ! git cat-file -e ${LINUX_SHA}^{commit} ; then
			# if not, fetch all of bpf-next; slow and painful
			git fetch bpf-next
		fi
		git reset --hard ${LINUX_SHA}
	fi

	travis_fold end pull_kernel_srcs
fi
