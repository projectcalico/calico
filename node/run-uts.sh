#!/bin/bash

# Turn off the annoying ginkgo warning.
# TODO: We should actually upgrade ginkgo!
export ACK_GINKGO_RC=true

if [ -z "$1" ]; then 
	echo "No packages need to be tested"
	exit 0
fi

# Go through each package we've been told to test. If there are actually test files present,
# then run those tests. If the package is included in UT_PACKAGES_TO_SKIP, we'll skip them.
for PKG in "$@"; do 
	# Skip any tests we've been told to skip.
	if [[ "$UT_PACKAGES_TO_SKIP" == *"$PKG"* ]]; then
	  echo "Skipping tests for package: ${PKG}"
	  continue
	fi

	HAS_TESTS=$(find ${PKG} -name "*_test.go")
	if [ ! -z "${HAS_TESTS}" ]; then 
		echo "Running tests for package: ${PKG}";
		ginkgo -r -skipPackage=${UT_PACKAGES_TO_SKIP} ${GINKGO_ARGS} ${PKG}; 
	else 
		echo "WARNING: No tests to run in ${PKG}, skipping"
	fi
done
