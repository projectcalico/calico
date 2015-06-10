.PHONEY: all node binary calico-build test ut ut-circle st clean setup-env

all: test

node:
	docker build -t calico/node .

binary: dist/calicoctl

calico-build: node
	cd build_calicoctl; docker build -t calico/build .

dist/calicoctl: calico-build
	mkdir -p dist
	chmod 777 dist

	# Ignore errors on both docker commands. CircleCI throws an beign error
	# from the use of the --rm flag

	# mount calico_containers and dist under /code work directory.  Don't use /code
	# as the mountpoint directly since the host permissions may not allow the
	# `user` account in the container to write to it.
	-docker run -v `pwd`/calico_containers:/code/calico_containers \
	 -v `pwd`/dist:/code/dist --rm \
	 -e PYTHONPATH=/code/calico_containers \
	 calico/build \
	 pyinstaller calico_containers/calicoctl.py -a -F -s --clean

	# mount calico_containers and dist under /code work directory.  Don't use /code
	# as the mountpoint directly since the host permissions may not allow the
	# `user` account in the container to write to it.
	-docker run -v `pwd`/calico_containers:/code/calico_containers \
	 -v `pwd`/dist:/code/dist --rm calico/build \
	 docopt-completion --manual-bash dist/calicoctl

test: ut st
ut: calico-build
	docker run --rm -v `pwd`/calico_containers:/code/calico_containers \
	calico/build bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	nosetests calico_containers/tests/unit -c nose.cfg'

ut-circle:
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run -v `pwd`/calico_containers:/code/calico_containers \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	calico/build bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	nosetests calico_containers/tests/unit -c nose.cfg \
	--cover-html-dir=dist --with-xunit --xunit-file=/circle_output/output.xml'

st: binary
	docker save --output calico_containers/calico-node.tar calico/node
	docker pull busybox:latest
	docker save --output calico_containers/busybox.tar busybox:latest
	dist/calicoctl checksystem --fix
	nosetests calico_containers/tests/st/ -sv --nologcapture

clean:
	find . -name '*.pyc' -exec rm -f {} +
	-rm -r dist
	docker rm -f calico-build
	docker rm -f calico-node
	docker rmi calico/node
	docker rmi calico/build

setup-env:
	virtualenv venv
	venv/bin/pip install --upgrade -r calico_containers/pycalico/requirements.txt
	venv/bin/pip install --upgrade -r build_calicoctl/requirements.txt
	@echo "run\n. venv/bin/activate"
	
