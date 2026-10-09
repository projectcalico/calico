BINDIR?=bin
ARCH?=amd64
KIND_VERSION?=v0.24.0
KUBE_VERSION?=v1.33.7
HELM_VERSION?=v3.16.3
GOMPLATE_VERSION?=v3.11.7
CRANE_VERSION?=v0.21.2

# Plain `curl --retry` gives up on a reset connection, which GitHub hands out
# under load; this retries every error.
REPO_ROOT:=$(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)
fetch_file = $(REPO_ROOT)/hack/fetch-file $(1) $(2)

KIND_CLUSTER_NAME?=kind

###############################################################################
# ASO management
###############################################################################
ASO_INSTALLED_MARKER:=.aso-installed

.PHONY: install-aso
install-aso: $(ASO_INSTALLED_MARKER)

$(ASO_INSTALLED_MARKER): $(BINDIR)/kind $(BINDIR)/kubectl $(BINDIR)/cmctl $(BINDIR)/asoctl $(BINDIR)/helm
	@echo "Creating kind cluster and installing aso ..."
	./install-aso.sh
	touch $@

.PHONY: uninstall-aso
uninstall-aso: $(BINDIR)/kind $(BINDIR)/kubectl
ifeq (,$(wildcard $(ASO_INSTALLED_MARKER)))
	@echo "ASO ready marker '$(ASO_INSTALLED_MARKER)' does not exist, doing nothing"
else
	@echo "ASO kind cluster will now be deleted"
	-$(BINDIR)/kind delete cluster --name $(KIND_CLUSTER_NAME)
	-rm -f kubeconfig
	-rm -f $(CURDIR)/kind-kubeconfig
	-rm -f $(ASO_INSTALLED_MARKER)
endif

###############################################################################
# Azure resource management
###############################################################################
# VMSS is azure VirtualMachineScaleSet.
# Current two VMSSes will be created (vmss-linux and vmss-windows)
# In this Makefile, we use the term "vmss" to represent all azure resources created by the process.
VMSS_MARKER:=.vmss-created

.PHONY: create-vmss
create-vmss: $(VMSS_MARKER)

$(VMSS_MARKER): $(BINDIR)/kubectl $(BINDIR)/gomplate $(ASO_INSTALLED_MARKER)
	@echo "Creating azure resources include vmss-linux and vmss-windows ..."
	./vmss.sh create
	./vmss.sh confirm-ssh
	touch $@

.PHONY: delete-vmss
delete-vmss: $(BINDIR)/kubectl
	@echo "Azure resources for cluster will be deleted..."
	./vmss.sh delete
	-rm -f $(VMSS_MARKER) $(KUBEADM_MARKER) $(CALICO_MARKER)

KUBEADM_MARKER:=.kubeadm-set-up

.PHONY: setup-kubeadm
setup-kubeadm: $(KUBEADM_MARKER)

$(KUBEADM_MARKER): $(ASO_INSTALLED_MARKER) $(VMSS_MARKER)
	@echo "Running setup-kubeadm ..."
	./install-kubeadm.sh
	touch $@

CALICO_MARKER:=.calico-installed

.PHONY: install-calico
install-calico: $(CALICO_MARKER)

$(CALICO_MARKER): $(KUBEADM_MARKER) $(BINDIR)/crane
	@echo "Installing Calico ..."
	./install-calico.sh
	touch $@

###############################################################################
# Utilities management
###############################################################################
HELPERS = ssh-node-linux.sh ssh-node-windows.sh scp-from-windows.sh scp-to-windows.sh

$(BINDIR)/kind:
	mkdir -p $(@D)
	$(call fetch_file,https://kind.sigs.k8s.io/dl/$(KIND_VERSION)/kind-linux-$(ARCH),$@)
	chmod +x $@
	touch $@

$(BINDIR)/kubectl:
	mkdir -p $(@D)
	@echo "Downloading kubectl version: $(KUBE_VERSION)"
	$(call fetch_file,https://dl.k8s.io/release/$(KUBE_VERSION)/bin/linux/$(ARCH)/kubectl,$@)
	chmod +x $@
	touch $@

$(BINDIR)/cmctl:
	mkdir -p $(@D)
	$(call fetch_file,https://github.com/cert-manager/cmctl/releases/latest/download/cmctl_linux_$(ARCH),$@)
	chmod +x $@
	touch $@

$(BINDIR)/asoctl:
	mkdir -p $(@D)
	$(call fetch_file,https://github.com/Azure/azure-service-operator/releases/latest/download/asoctl-linux-$(ARCH).gz,$(BINDIR)/asoctl.gz)
	gunzip $(BINDIR)/asoctl.gz
	chmod +x $@
	touch $@

$(BINDIR)/gomplate:
	mkdir -p $(@D)
	$(call fetch_file,https://github.com/hairyhenderson/gomplate/releases/download/$(GOMPLATE_VERSION)/gomplate_linux-$(ARCH),$@)
	chmod +x $@
	touch $@

$(BINDIR)/helm:
	mkdir -p $(@D)
	$(call fetch_file,https://get.helm.sh/helm-$(HELM_VERSION)-linux-$(ARCH).tar.gz,$(BINDIR)/helm.tar.gz)
	tar -xzf $(BINDIR)/helm.tar.gz -C $(BINDIR) --strip-components=1 linux-$(ARCH)/helm
	rm $(BINDIR)/helm.tar.gz
	chmod +x $@
	touch $@

CRANE_ARCH = $(subst amd64,x86_64,$(ARCH))
$(BINDIR)/crane:
	mkdir -p $(@D)
	$(call fetch_file,https://github.com/google/go-containerregistry/releases/download/$(CRANE_VERSION)/go-containerregistry_Linux_$(CRANE_ARCH).tar.gz,/tmp/crane.tar.gz)
	tar xz -C $(@D) -f /tmp/crane.tar.gz crane && rm -f /tmp/crane.tar.gz
	touch $@

.PHONY: clean
clean: delete-vmss uninstall-aso
	-rm -rf connect.txt
	-rm -f password.txt
	-rm -rf ./report
	-rm -f .sshkey .sshkey.pub
	-rm -f $(HELPERS)
	-rm -f kubeadm-config.yaml
	-rm -f operator-crds.yaml tigera-operator.yaml tigera-prometheus-operator.yaml cert-manager.yaml kube-proxy-windows.yaml
	-rm -rf infra/manifests/
	-rm -rf EE/manifests/
	-rm -rf OSS/manifests/
	-rm -rf windows/kubeadm/
	-rm -f windows/config

.PHONY: dist-clean
dist-clean: clean
	-rm -rf $(BINDIR)
	-rm -f $(VMSS_MARKER) $(ASO_INSTALLED_MARKER) $(KUBEADM_MARKER) $(CALICO_MARKER)
