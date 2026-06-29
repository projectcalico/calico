include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/whisker-backend

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

clean:
	rm -rf bin

# Update protobuf generation.
protobuf proto/api.pb.go: proto/api.proto
	$(DOCKER_RUN) -v $(CURDIR):/code \
		$(CALICO_BUILD) sh -c 'protoc --proto_path=/code/proto --go_out=/code/proto --go-grpc_out=. --go_opt=paths=source_relative /code/proto/api.proto'
	$(MAKE) fix-changed

###############################################################################
# UTs
###############################################################################
ci: static-checks ut
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) gotestsum --junitfile report/whisker_backend_ut.xml -- ./... -cover -count 1
