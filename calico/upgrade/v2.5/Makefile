dist/clis:
	mkdir -p dist
	curl -sSf -L https://github.com/projectcalico/calicoctl/releases/download/v1.4.1/calicoctl -o dist/calicoctl-v1.4
	curl -sSf -L https://github.com/projectcalico/calicoctl/releases/download/v1.5.0/calicoctl -o dist/calicoctl-v1.5
	curl -sSf -L https://storage.googleapis.com/kubernetes-release/release/v1.7.4/bin/linux/amd64/kubectl -o dist/kubectl
	chmod +x dist/calicoctl-v1.4
	chmod +x dist/calicoctl-v1.5
	chmod +x dist/kubectl

build-container: dist/clis
	docker build -t calico/v2.5-upgrade:v0.0.1 .

clean:
	rm -rf dist
