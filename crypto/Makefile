PACKAGE_NAME = github.com/projectcalico/calico/crypto

include ../metadata.mk
include ../lib.Makefile

.PHONY: ci
ci: fv

.PHONY: fv
fv: setup-fv bin/fips-test-build
	# Run a server using the FIPS strict mode settings and wait 1s to let it come up.
	$(DOCKER_RUN) --name fips-test-build --rm -d $(CALICO_BUILD) ./bin/fips-test-build
	sleep 1
	# The server should respond with the value for STRICT_FIPS.
	$(DOCKER_RUN) $(CALICO_BUILD) curl -k  https://localhost:8083 | grep true
	# Run the nmap tool on the server to find out the tls versions and ciphers.
	docker run --net=host --rm -it instrumentisto/nmap --script ssl-enum-ciphers -p 8083 127.0.0.1 > tmp/nmap.log
	# remove times and dates from file
	sed -i '1,4d;22d' tmp/nmap.log
	docker rm -f fips-test-build
	# If the ciphers are as expected, we get exit code 0.
	diff -u fv/expected-nmap.log tmp/nmap.log

bin/fips-test-build:
	$(call build_cgo_boring_binary, $(PACKAGE_NAME)/fv/main, $@)

setup-fv:
	mkdir -p bin tmp
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'openssl req -batch -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -keyout tmp/tls.key -out tmp/tls.crt'
