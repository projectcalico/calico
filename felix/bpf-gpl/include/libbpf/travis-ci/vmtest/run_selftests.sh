#!/bin/bash

set -euo pipefail

source $(cd $(dirname $0) && pwd)/helpers.sh

test_progs() {
	if [[ "${KERNEL}" != '4.9.0' ]]; then
		travis_fold start test_progs "Testing test_progs"
		./test_progs ${BLACKLIST:+-b$BLACKLIST} ${WHITELIST:+-t$WHITELIST}
		travis_fold end test_progs
	fi

	travis_fold start test_progs-no_alu32 "Testing test_progs-no_alu32"
	./test_progs-no_alu32 ${BLACKLIST:+-b$BLACKLIST} ${WHITELIST:+-t$WHITELIST}
	travis_fold end test_progs-no_alu32
}

test_maps() {
	travis_fold start test_maps "Testing test_maps"
	./test_maps
	travis_fold end test_maps
}

test_verifier() {
	travis_fold start test_verifier "Testing test_verifier"
	./test_verifier
	travis_fold end test_verifier
}

travis_fold end vm_init

configs_path='libbpf/travis-ci/vmtest/configs'
blacklist_path="$configs_path/blacklist/BLACKLIST-${KERNEL}"
if [[ -s "${blacklist_path}" ]]; then
	BLACKLIST=$(cat "${blacklist_path}" | cut -d'#' -f1 | tr -s '[:space:]' ',')
fi

whitelist_path="$configs_path/whitelist/WHITELIST-${KERNEL}"
if [[ -s "${whitelist_path}" ]]; then
	WHITELIST=$(cat "${whitelist_path}" | cut -d'#' -f1 | tr -s '[:space:]' ',')
fi

cd libbpf/selftests/bpf

test_progs

if [[ "${KERNEL}" == 'latest' ]]; then
	#test_maps
	test_verifier
fi
