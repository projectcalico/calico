include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/goldmane

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

clean:
	rm -rf bin

# Build the testserver image.
.PHONY: testserver
calico/flowgen: bin/flowgen
	docker build -t calico/flowgen -f docker/flowgen/Dockerfile .

bin/flowgen: $(shell find . -name '*.go')
	$(call build_binary, $(PACKAGE_NAME)/cmd/flowgen, $@)

# Update protobuf generation.
protobuf proto/api.pb.go: proto/api.proto
	$(DOCKER_RUN) -v $(CURDIR):/code $(CALICO_BUILD) sh -c 'protoc --proto_path=/code/proto --go_out=/code/proto --go-grpc_out=. --go_opt=paths=source_relative /code/proto/api.proto'
	$(MAKE) fix-changed

###############################################################################
# Run Benchmark Tests
###############################################################################
.PHONY: benchmark
benchmark:
	@go test ./... -bench=. -benchmem -benchtime=10s -run=^$$ | \
    	grep -vE '^\?|\s\[no test files\]|^ok\s|^PASS$$'

###############################################################################
# Generate files
###############################################################################
GENERATED_FILES=proto/api.pb.go
gen-files: $(GENERATED_FILES) gen-mocks

###############################################################################
# UTs
###############################################################################
ci: static-checks ut
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) gotestsum --junitfile report/goldmane_ut.xml -- ./... -coverprofile coverage.profile -race -count 1

gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'mockery'
