BINDIR?=bin
ARCH?=amd64
KIND_VERSION?=v0.24.0
KUBE_VERSION?=v1.33.6
HELM_VERSION?=v3.16.3

###############################################################################
# ASO management
###############################################################################
ASO_INSTALLED_MARKER:=.aso_installed

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
	-$(BINDIR)/kind delete cluster --name kind
	-rm -f kubeconfig
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

$(VMSS_MARKER): $(BINDIR)/kubectl $(BINDIR)/gomplate
	@echo "Creating azure resources include vmss-linux and vmss-windows ..."
	./vmss.sh create
	./vmss.sh confirm-ssh
	touch $@

.PHONY: delete-vmss
delete-vmss: $(BINDIR)/kubectl
	@echo "Azure resources for cluster will be deleted..."
	./vmss.sh delete
	-rm -f $(VMSS_MARKER)

.PHONY: setup-kubeadm
setup-kubeadm: $(ASO_INSTALLED_MARKER) $(VMSS_MARKER)
	@echo "Running setup-kubeadm ..."
	./install-kubeadm.sh

.PHONY: install-calico
install-calico:
	@echo "Installing Calico ..."
	./install-calico.sh

###############################################################################
# Utilities management
###############################################################################
HELPERS = ssh-node-linux.sh ssh-node-windows.sh scp-from-windows.sh scp-to-windows.sh

$(BINDIR)/kind:
	mkdir -p $(@D)
	curl -sSf -L --retry 5 https://kind.sigs.k8s.io/dl/$(KIND_VERSION)/kind-linux-$(ARCH) -o $@
	chmod +x $@
	touch $@

$(BINDIR)/kubectl:
	mkdir -p $(@D)
	@echo "Downloading kubectl version: $(KUBE_VERSION)"
	curl -sSf -L --retry 5 https://dl.k8s.io/release/$(KUBE_VERSION)/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $@
	touch $@

$(BINDIR)/cmctl:
	mkdir -p $(@D)
	curl -sSf -L --retry 5 https://github.com/cert-manager/cmctl/releases/latest/download/cmctl_linux_amd64 -o $@
	chmod +x $@
	touch $@

$(BINDIR)/asoctl:
	mkdir -p $(@D)
	curl -sSf -L --retry 5 https://github.com/Azure/azure-service-operator/releases/latest/download/asoctl-linux-amd64.gz -o $(BINDIR)/asoctl.gz
	gunzip $(BINDIR)/asoctl.gz
	chmod +x $@
	touch $@

$(BINDIR)/gomplate:
	mkdir -p $(@D)
	curl -sSf -L --retry 5 https://github.com/hairyhenderson/gomplate/releases/download/v3.11.7/gomplate_linux-amd64 -o $@
	chmod +x $@
	touch $@

$(BINDIR)/helm:
	mkdir -p $(@D)
	curl -sSf -L --retry 5 https://get.helm.sh/helm-$(HELM_VERSION)-linux-$(ARCH).tar.gz -o $(BINDIR)/helm.tar.gz
	tar -xzf $(BINDIR)/helm.tar.gz -C $(BINDIR) --strip-components=1 linux-$(ARCH)/helm
	rm $(BINDIR)/helm.tar.gz
	chmod +x $@
	touch $@

.PHONY: clean
clean: delete-vmss uninstall-aso
	-rm -rf connect.txt
	-rm -f password.txt
	-rm -rf ./report
	-rm -f .sshkey .sshkey.pub
	-rm -f $(HELPERS)
	-rm -f operator-crds.yaml tigera-operator.yaml tigera-prometheus-operator.yaml
	-rm -rf infra/manifests/
	-rm -rf windows/kubeadm/
	-rm -f windows/config

.PHONY: dist-clean
dist-clean: clean
	-rm -rf $(BINDIR)
	-rm -f $(VMSS_MARKER) $(ASO_INSTALLED_MARKER)
