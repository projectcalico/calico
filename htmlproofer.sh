#!/bin/bash
# This file executes htmlproofer checks on the compiled html files in _site.

# Version of htmlproofer to use.
HP_VERSION=v0.2

# Local directories to ignore when checking external links
HP_IGNORE_LOCAL_DIRS="/v1.5/,/v1.6/,/v2.0/,/v2.1/,/v2.2/,/v2.3/,/v2.4/,/v2.5/,/v2.6/,/v3.0/"

# URLs to ignore when checking external links.
HP_IGNORE_URLS="/docs.openshift.org/,#,/github.com\/projectcalico\/calico\/releases\/download/"

# The htmlproofer check is flaky, so we retry a number of times if we get a bad result.
# If it doesn't pass once in 10 tries, we count it as a failed check.
echo "Running a hard URL check against recent releases"
for i in `seq 1 3`; do
	echo "htmlproofer attempt #${i}"
	docker run -ti -e JEKYLL_UID=`id -u` --rm -v $(pwd)/_site:/_site/ quay.io/calico/htmlproofer:${HP_VERSION} /_site --file-ignore ${HP_IGNORE_LOCAL_DIRS} --assume-extension --check-html --empty-alt-ignore --url-ignore ${HP_IGNORE_URLS} --internal_domains "docs.projectcalico.org"

	# Store the RC for future use.
	rc=$?
	echo "htmlproofer rc: $rc"

	# If the command executed successfully, break out. Otherwise, retry.
	if [[ $rc == 0 ]]; then break; fi

	# Otherwise, sleep a short period and then retry.
	echo "htmlproofer failed, retry in 10s"
	sleep 10
done

# Exit using the return code from the loop above.
exit $rc
