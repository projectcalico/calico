BINDIR?=bin
ARCH?=amd64
KIND_VERSION?=v0.22.0

###############################################################################
# ASO management
###############################################################################
ASO_INSTALLED_MARKER:=.aso_installed

.PHONY: install-aso
install-aso: $(ASO_INSTALLED_MARKER)

$(ASO_INSTALLED_MARKER): $(BINDIR)/kind $(BINDIR)/kubectl $(BINDIR)/cmctl $(BINDIR)/asoctl
	@echo "Creating kind cluster and installing aso ..."
	./install-aso.sh
	touch $@

.PHONY: uninstall-aso
uninstall-aso: $(BINDIR)/kind $(BINDIR)/kubectl
ifeq (,$(wildcard $(ASO_INSTALLED_MARKER)))
	@echo "ASO ready marker '$(ASO_INSTALLED_MARKER)' does not exist, doing nothing"
else
	@echo "Azure resources for cluster $(CLUSTER_NAME_CAPZ) will now be deleted, this can take up to 20 minutes"
	-$(BINDIR)/kind delete cluster --name kind${SUFFIX} 
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
	./vmss.sh show
	touch $@

.PHONY: delete-vmss
delete-vmss: $(BINDIR)/kubectl
ifeq (,$(wildcard $(VMSS_MARKER)))
	@echo "VMSS ready marker '$(VMSS_MARKER)' does not exist, doing nothing"
else
	@echo "Azure resources for cluster will be deleted..."
	-$(BINDIR)/kubectl delete ns winfv
	-rm -f $(VMSS_MARKER)
endif

###############################################################################
# FV management
###############################################################################
.PHONY: run-fv
run-fv: $(ASO_INSTALLED_MARKER) $(VMSS_MARKER)
	@echo "Running FV ..."
	./setup-fv.sh

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

.PHONY: clean
clean: delete-vmss uninstall-aso
	-rm -rf connect.txt
	-rm -f password.txt
	-rm -rf ./report
	-rm -f .sshkey .sshkey.pub
	-rm -f $(HELPERS)

.PHONY: dist-clean
dist-clean: clean
	-rm -rf $(BINDIR)
	-rm -f $(VMSS_MARKER) $(ASO_INSTALLED_MARKER)
