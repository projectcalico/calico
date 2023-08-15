include ../../metadata.mk
include ../../lib.Makefile

# We only ever release from the tip of a release branch.
GIT_TOPLEVEL=$(shell git rev-parse --show-toplevel)
PYTHON_DOCKER_IMAGE?=python:3.11

# Meant to be run on the remote VM
update-versions:
	@docker run --rm -v $(GIT_TOPLEVEL):/work -w /work $(PYTHON_DOCKER_IMAGE) /work/hack/versions/prepare_update_versions.sh
