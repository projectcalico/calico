#!/bin/bash

script_dir="$(dirname "$0")"
source ${script_dir}/utils.sh

declare -a TESTS_TO_RUN=( 'mesh/ipip-always'
                          'mesh/ipip-cross-subnet'
                          'mesh/ipip-off' )

success=0

for test in "${TESTS_TO_RUN[@]}"; do
    echo "Testing ${test}"
    if ! . ${script_dir}/test_kdd.sh ${test}; then
        success=1
    fi
    clean_kdd
done

exit ${success}