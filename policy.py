import os
import sys
import json
import yaml
import requests
from prettytable import PrettyTable

# Get the command
command = sys.argv[1]

# Get the API location.
KUBE_API = os.environ.get("KUBE_API_ROOT", "http://localhost:8080")

if command == "create":
    # Load the policy.
    input_raw = ''.join(sys.stdin.readlines())
    input_loaded = yaml.load(input_raw) 
     
    # Get the namespace
    namespace = input_loaded["metadata"].get("namespace", "default")
    name = input_loaded["metadata"]["name"]

    #print "POST NetworkPolicy: \n%s" % json.dumps(input_loaded, indent=2)
    url = "%s/apis/net.alpha.kubernetes.io/v1alpha1/namespaces/%s/networkpolicys" % (KUBE_API, namespace)
    resp = requests.post(url, data=json.dumps(input_loaded))

    if resp.status_code != 201:
        print "POST to url: %s" % url
        print resp.text
    else:
        print "Successfully created policy %s/%s" % (namespace, name)
elif command == "delete":
    namespace = sys.argv[2]
    policy = sys.argv[3]
    url = "%s/apis/net.alpha.kubernetes.io/v1alpha1/namespaces/%s/networkpolicys/%s" % (KUBE_API, namespace, policy)
    resp = requests.delete(url)
    if resp.status_code != 200:
        print "DELETE to url: %s" % url
        print resp.text
    else:
        print "Successfully deleted policy %s/%s" % (namespace, policy)
elif command == "list":
    url = "%s/apis/net.alpha.kubernetes.io/v1alpha1/networkpolicys" % (KUBE_API)
    resp = requests.get(url)
    if resp.status_code != 200:
        print resp.text
        sys.exit(1)

    t = PrettyTable(["Namespace", "Name"])
    for policy in resp.json()["items"]:
        namespace = policy["metadata"].get("namespace", "default")
        name = policy["metadata"]["name"]
        t.add_row([namespace, name])
    print t
elif command == "get":
    namespace = sys.argv[2]
    policy = sys.argv[3]
    url = "%s/apis/net.alpha.kubernetes.io/v1alpha1/namespaces/%s/networkpolicys/%s" % (KUBE_API, namespace, policy)
    resp = requests.get(url)
    if resp.status_code != 200:
        print "GET to url: %s" % url
        print resp
    print "%s" % json.dumps(json.loads(resp.text), indent=2)
else:
    print "Invalid command: %s" % command
