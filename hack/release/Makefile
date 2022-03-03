include ../../metadata.mk
include ../../lib.Makefile

# Build a release from the currently checked out commit.
# Uses SSH to run commands on the remote builder.
release: .vm.created
	$(./bin/terraform output connect_command) -- cd calico && git fetch && checkout $(GIT_VERSION)
	$(./bin/terraform output connect_command) -- cd calico && make release

# Create a VM using the given vars.
VAR_FILE ?= terraform.tfvars
apply:  .vm.created
.vm.created: .terraform.init
	./bin/terraform apply --auto-approve -var-file=$(VAR_FILE)

# Destroy the VM.
destroy:
	./bin/terraform destroy --auto-approve -var-file=$(VAR_FILE)
	rm -f .vm.created

# Tear down any existing VM, and create a new one.
rebuild:
	$(MAKE) destroy apply

# Initialize the terraform install.
.terraform.init: bin/terraform
	./bin/terraform init && touch $@

# Install the terraform binary.
bin/terraform: bin/terraform.zip
	unzip bin/terraform.zip -d bin && touch $@
bin/terraform.zip:
	mkdir -p bin
	wget https://releases.hashicorp.com/terraform/1.1.7/terraform_1.1.7_linux_amd64.zip -O $@
