import sys
import json
import pycalico

def main():
    stdin_raw_data = sys.stdin.read()

    # Convert input data to JSON object
    try:
        stdin_json = json.loads(stdin_raw_data)
    except ValueError as e:
        quit_with_error(str(e))

    # Extract command
    try:
        command = stdin_json['command']
    except KeyError:
        quit_with_error("Missing command")

    # Extract args
    try:
        args = stdin_json['args']
    except KeyError:
        quit_with_error("Missing arguments")

    # Call command with args
    if command == 'prepare':
        prepare(args)
    elif command == 'isolate':
        isolate(args)
    elif command == 'update':
        update(args)
    elif command == 'cleanup':
        cleanup(args)
    else:
        quit_with_error("Unknown command: %s" % command)

def prepare(args):
    """
    "args": {
        "hostname": "slave-H3A-1", # Required
        "container-id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a", # Required
        "ipv4_addrs": ["192.168.23.4"], # Required, can be []
        "ipv6_addrs": ["2001:3ac3:f90b:1111::1"], # Required, can be []
        "netgroups": ["prod", "frontend"], # Required.
        "labels": {  # Optional.
            "rack": "3A",
            "pop": "houston"
    }
    """
    pass


def isolate(args):
    """
    "args": {
        "hostname": "slave-H3A-1", # Required
        "container-id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a", # Required
        "pid": 3789 # Required
    }
    """
    pass


def update(args):
    pass


def cleanup(args):
    """
    "args": {
        "hostname": "slave-H3A-1", # Required
        "container-id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a" # Required
    }
    """
    pass



def quit_with_error(msg=None):
    """
    Print error JSON, then quit
    """
    error_msg = json.dumps({"error": msg})
    print error_msg
    sys.exit(1)


if __name__ == '__main__':
    main()
    quit_with_error()