#!/bin/bash
set -e
set -x
gcloud compute instances delete -q master || true
gcloud compute instances create master --image https://www.googleapis.com/compute/v1/projects/coreos-cloud/global/images/coreos-alpha-618-0-0-v20150312 --machine-type g1-small --metadata-from-file user-data=cloud-config-master.yaml --can-ip-forward
gcloud compute firewall-rules create "any" --allow tcp:1-65535 --network "default" --source-ranges "192.168.0.0/16" || true
