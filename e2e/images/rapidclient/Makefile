include ../../../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e/images/rapidclient
include ../../../lib.Makefile

QUAY_REGISTRY ?= quay.io/tigeradev
TAG_NAME ?= $(shell git branch --show-current)

build: bin/rapidclient

bin/rapidclient: main.go
	mkdir -p bin
	$(DOCKER_RUN) -e CGO_ENABLED=0 $(CALICO_BUILD) go build -o $@ -ldflags "-s -w" .

image: bin/rapidclient
	docker buildx build --load --platform=linux/$(ARCH) --pull \
		--build-arg BINARY_PATH=bin/rapidclient \
		-f Dockerfile \
		-t $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME) .

publish: image
	docker push $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME)
	@if [ "$(TAG_NAME)" = "master" ]; then \
		docker tag $(QUAY_REGISTRY)/rapidclient:$(TAG_NAME) $(QUAY_REGISTRY)/rapidclient:latest; \
		docker push $(QUAY_REGISTRY)/rapidclient:latest; \
		echo "Pushed $(QUAY_REGISTRY)/rapidclient:latest"; \
	fi

clean:
	rm -rf bin/

