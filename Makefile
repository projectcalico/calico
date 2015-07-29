.PHONEY: binary

binary: dist/calico

dist/calico:
	# Build docker container
	cd build_calico_rkt; docker build -t calico-rkt-build .
	mkdir -p dist
	chmod 777 `pwd`/dist
	
	# Build the rkt plugin
	docker run \
	-u user \
	-v `pwd`/calico_rkt:/code/calico_rkt \
	-v `pwd`/dist:/code/dist \
	-e PYTHONPATH=/code/calico_rkt \
	calico-rkt-build pyinstaller calico_rkt/calico_rkt.py -a -F -s --clean
