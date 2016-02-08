import os
import sys
import json
import yaml
import requests

# Get the API location.
KUBE_API = os.environ.get("KUBE_API_ROOT", "http://localhost:8080")

# Load the policy.
input_raw = ''.join(sys.stdin.readlines())
input_loaded = yaml.load(input_raw) 

# Print it out.
print "POST NetworkPolicy: \n%s" % json.dumps(input_loaded, indent=2)

url = "%s/apis/net.alpha.kubernetes.io/v1alpha1/namespaces/default/networkpolicys" % KUBE_API
requests.post(url, data=input_loaded)
