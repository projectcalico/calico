BINDIR?=bin
ARCH?=amd64

###############################################################################
# Cluster management
###############################################################################
CLUSTER_CREATED_MARKER:=.cluster_created

.PHONY: create-cluster
create-cluster: $(CLUSTER_CREATED_MARKER)

$(CLUSTER_CREATED_MARKER): $(BINDIR)/kind $(BINDIR)/kubectl $(BINDIR)/clusterctl $(BINDIR)/yq
	@echo "Creating cluster $(CLUSTER_NAME_CAPZ) ..."
	./create-cluster.sh
	$(MAKE) generate-helpers
	./bootstrap-cluster-ips.sh
	./replace-win-containerd.sh
	touch $@

.PHONY: delete-cluster
delete-cluster: $(BINDIR)/kind $(BINDIR)/kubectl
	@echo "Azure resources for cluster $(CLUSTER_NAME_CAPZ) will now be deleted, this can take up to 20 minutes"
	-$(BINDIR)/kubectl delete cluster $(CLUSTER_NAME_CAPZ)
	-$(BINDIR)/kind delete cluster --name kind${SUFFIX}
	-az group delete --name $(CI_RG) -y
	-rm -f kubeconfig
	-rm -f win-capz.yaml
	-rm -f tigera-operator.yaml
	-rm -f tigera-prometheus-operator.yaml
	-rm -f $(HELPERS)
	-rm -f $(CLUSTER_CREATED_MARKER) $(CALICO_INSTALLED_MARKER)

CALICO_INSTALLED_MARKER:=.calico_installed

.PHONY: install-calico
install-calico: $(CALICO_INSTALLED_MARKER)

$(CALICO_INSTALLED_MARKER): $(CLUSTER_CREATED_MARKER) $(BINDIR)/kubectl
	./install-calico.sh
	touch $@

###############################################################################
# Utilities management
###############################################################################
HELPERS = scp-to-node.sh ssh-node.sh scp-from-node.sh
$(HELPERS): generate-helpers

.PHONY: generate-helpers
generate-helpers: .sshkey .sshkey.pub
	./generate-helpers.sh

$(BINDIR)/kind:
	mkdir -p $(@D)
	curl -sSf -L --retry 5 https://kind.sigs.k8s.io/dl/$(KIND_VERSION)/kind-linux-$(ARCH) -o $@
	chmod +x $@
	touch $@

$(BINDIR)/kubectl:
	mkdir -p $(@D)
	curl -sSf -L --retry 5 https://dl.k8s.io/release/$(KUBE_VERSION)/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $@
	touch $@

$(BINDIR)/clusterctl:
	mkdir -p $(@D)
	curl -sSf -L --retry 5 https://github.com/kubernetes-sigs/cluster-api/releases/download/$(CLUSTER_API_VERSION)/clusterctl-linux-$(ARCH) -o $(BINDIR)/clusterctl
	chmod +x $@
	touch $@
	$(BINDIR)/clusterctl version

$(BINDIR)/yq:
	mkdir -p $(@D)
	curl -sSf -L --retry 5 https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_linux_$(ARCH) -o $(BINDIR)/yq
	chmod +x $@
	touch $@

.PHONY: clean
clean:
	-rm -f kubeconfig
	-rm -f win-capz.yaml
	-rm -f tigera-operator.yaml
	-rm -f .sshkey .sshkey.pub
	-rm -f $(HELPERS)
	-rm -f az-output.log

.PHONY: dist-clean
dist-clean: clean
	-rm -rf $(BINDIR)
	-rm -f $(CLUSTER_CREATED_MARKER) $(CALICO_INSTALLED_MARKER)
	-rm -f *.log
