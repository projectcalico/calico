include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/app-policy

###############################################################################

GENERATED_FILES=../felix/proto/felixbackend.pb.go proto/healthz.pb.go

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.
SRC_FILES += $(GENERATED_FILES)

## Run the tests for the current platform/architecture
test: ut

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf bin report

.PHONY: clean-generated
# Delete (checked-in) generated files. Intentionally not part of the main clean target since these files are
# checked in and deleting them makes the repo "dirty" as far as git is concerned.
clean-generated:
	rm -rf $(GENERATED_FILES)

###############################################################################
# Protobufs,
#
# 1. defer to felix's makefile for felixbackend stuff
# 2. build proto for healthz
###############################################################################

../felix/proto/felixbackend.pb.go: ../felix/proto/felixbackend.proto
	$(MAKE) --directory ../felix protobuf

protobuf: $(GENERATED_FILES)

proto/healthz.pb.go: proto/healthz.proto
	$(DOCKER_RUN) -v $(CURDIR)/proto:/proto:rw \
		$(CALICO_BUILD) \
			sh -c 'protoc --proto_path=/proto --go_out=/proto --go-grpc_out=. --go_opt=paths=source_relative healthz.proto'
	$(MAKE) fix-changed

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: protobuf
	mkdir -p report
	$(DOCKER_RUN) $(CALICO_BUILD) /bin/bash -c "cd /go/src/$(PACKAGE_NAME) && gotestsum --junitfile report/app_policy_ut.xml -- -v ./..."

###############################################################################
# CI
###############################################################################

.PHONY: ci
ci: mod-download check-generated-files static-checks ut

## Check if generated files are out of date
.PHONY: check-generated-files
check-generated-files:
	$(MAKE) clean
	$(MAKE) protobuf
	if (git describe --tags --dirty | grep -c dirty >/dev/null); then \
	  echo "Generated files are out of date."; \
	  false; \
	else \
	  echo "Generated files are up to date."; \
	fi
