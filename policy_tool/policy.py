import os
import sys
import json
import yaml
import requests
from docopt import docopt
from prettytable import PrettyTable

__doc__ = """
Usage:
    policy create [--namespace=<namespace>] [-f <filename>]
    policy delete [--namespace=<namespace>] <policy>
    policy get [--namespace=<namespace>] <policy>
    policy list
    policy help

Description:
    Helper for creating, deleting, and listing Kubernetes
    NetworkPolicy objects.

Options:
    --namespace=<namespace>             Kubernetes namespace to use.
                                        [default: default]
    -f --file                           Create from the provided file.

"""

# Parse the given arguments.
command_args = docopt(__doc__)

# Get the namespace
namespace = command_args.get("--namespace")

# Get the API location and token from environment variables.
KUBE_API = os.environ.get("KUBE_API_ROOT", "http://localhost:8080")
AUTH_TOKEN = os.environ.get("KUBE_AUTH_TOKEN")

CA_PATH = os.environ.get("CA_PATH", "ca.pem")
ca_exists = os.path.exists(CA_PATH)

CA_KEY_PATH = os.environ.get("CA_KEY_PATH", "ca_key.pem")
ca_key_exists = os.path.exists(CA_KEY_PATH)

# For use in requests.
CERT = (CA_PATH, CA_KEY_PATH)
req_args = {"verify": CA_PATH if ca_exists else False,
            "cert": CERT if ca_exists else None}

session = requests.Session()
if AUTH_TOKEN:
    session.headers.update({'Authorization': 'Bearer ' + AUTH_TOKEN})

if command_args.get("create"):
    use_file = command_args.get("--file")
    if use_file:
        # If a file is provided, read from the file.
        filename = command_args.get("<filename>")
        if not filename:
            print("Missing parameter: <filename>")
            sys.exit(1)

        with open(filename) as f:
            input_raw = f.read()
    else:
        # Read from stdin.
        print("Reading input from stdin")
        input_raw = ''.join(sys.stdin.readlines())

    # Load the given input.
    input_loaded = yaml.load(input_raw)

    # Get the namespace
    try:
        namespace = input_loaded["metadata"].get("namespace", namespace)
        name = input_loaded["metadata"]["name"]
    except (TypeError, KeyError, AttributeError), e:
        print("Invalid NetworkPolicy - unable to parse metadata.")
        sys.exit(1)

    url = "%s/apis/net.alpha.kubernetes.io/v1alpha1/namespaces/%s/networkpolicys" % (KUBE_API, namespace)
    resp = session.post(url, data=json.dumps(input_loaded), **req_args)

    if resp.status_code != 201:
        print "POST to url: %s" % url
        print resp.text
    else:
        print "Successfully created policy %s/%s" % (namespace, name)
elif command_args.get("delete"):
    policy = command_args.get("<policy>")
    url = "%s/apis/net.alpha.kubernetes.io/v1alpha1/namespaces/%s/networkpolicys/%s" % (KUBE_API, namespace, policy)
    resp = session.delete(url, **req_args)
    if resp.status_code != 200:
        print "DELETE to url: %s" % url
        print resp.text
    else:
        print "Successfully deleted policy %s/%s" % (namespace, policy)
elif command_args.get("list"):
    url = "%s/apis/net.alpha.kubernetes.io/v1alpha1/networkpolicys" % (KUBE_API)
    resp = session.get(url, **req_args)
    if resp.status_code != 200:
        print resp.text
        sys.exit(1)

    t = PrettyTable(["Namespace", "Name"])
    for policy in resp.json()["items"]:
        namespace = policy["metadata"].get("namespace", "default")
        name = policy["metadata"]["name"]
        t.add_row([namespace, name])
    print t
elif command_args.get("get"):
    policy = command_args.get("<policy>")
    url = "%s/apis/net.alpha.kubernetes.io/v1alpha1/namespaces/%s/networkpolicys/%s" % (KUBE_API, namespace, policy)
    resp = session.get(url, **req_args)
    if resp.status_code != 200:
        print "GET to url: %s" % url
        print resp
    print "%s" % json.dumps(json.loads(resp.text), indent=2)
else:
    print(__doc__)
