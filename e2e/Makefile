include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e
include ../lib.Makefile

QUAY_REGISTRY ?= quay.io/tigeradev
TAG_NAME ?= $(shell git branch --show-current)

SRC_FILES=$(shell find pkg -name '*.go')
build: bin/k8s/e2e.test bin/adminpolicy/e2e.test $(SRC_FILES)
bin/k8s/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/k8s -c -o $@

bin/adminpolicy/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/adminpolicy -c -o $@

bin/rapidclient: images/rapidclient/main.go
	mkdir -p bin
	$(DOCKER_RUN) -e CGO_ENABLED=0 $(CALICO_BUILD) go build -o $@ -ldflags "-s -w" ./images/rapidclient

###############################################################################
# test images
###############################################################################
test-images: bin/rapidclient
	docker buildx build --load --platform=linux/$(ARCH) --pull \
		--build-arg BINARY_PATH=bin/rapidclient \
		-f images/rapidclient/Dockerfile \
		-t $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME) .
	@if [ "$(TAG_NAME)" = "master" ]; then \
		docker tag $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME) $(QUAY_REGISTRY)/rapidclient:latest; \
		echo "Tagged $(QUAY_REGISTRY)/rapidclient:latest"; \
	fi

publish-test-images: test-images
	docker push $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME)
	@if [ "$(TAG_NAME)" = "master" ]; then \
		docker push $(QUAY_REGISTRY)/rapidclient:latest; \
		echo "Pushed $(QUAY_REGISTRY)/rapidclient:latest"; \
	fi

clean:
	rm -rf bin/
