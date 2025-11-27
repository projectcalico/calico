## Windows FV infrastructure
This directory contains scripts and manifests to setup Windows cni-plugin FV infrastructure.

### Prerequisite
azure cli has been installed. 

### Steps
1. Set environment variables in `export-env.sh`.

2. Run `make run-fv`.

### Access Linux or Windows nodes

Helper scripts will be generated to ssh or scp into each node. See individual script for details.

### Cleanup
Run `make dist-clean`.
