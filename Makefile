.PHONY: all binary ut clean

BUILD_DIR=build_calico_rkt
BUILD_FILES=Dockerfile requirements.txt

default: all
all: binary test
binary: dist/calico_rkt
test: ut

# Build a new docker image to be used by binary or tests
rktbuild.created: $(BUILD_FILES)
	docker build -t calico/rkt-build .
	touch rktbuild.created

dist/calico_rkt: rktbuild.created
	mkdir -p dist
	chmod 777 `pwd`/dist
	
	# Build the rkt plugin
	docker run \
	-u user \
	-v `pwd`/calico_rkt:/code/calico_rkt \
	-v `pwd`/dist:/code/dist \
	-e PYTHONPATH=/code/calico_rkt \
	calico/rkt-build pyinstaller calico_rkt/calico_rkt.py -a -F -s --clean

ut: dist/calico_rkt
	docker run --rm -v `pwd`/calico_rkt:/code/calico_rkt \
	-v `pwd`/nose.cfg:/code/nose.cfg \
	calico/rkt-build bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	PYTHONPATH=/code/calico_rkt nosetests calico_rkt/tests -c nose.cfg'

clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-docker rm -f calico-build
	-docker rmi calico/rkt-build
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes

