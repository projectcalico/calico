#!/bin/bash

# Get the SSH command, and use eval to remove the quotes from it.
ssh=$(./bin/terraform output connect_command)
ssh=$(eval echo $ssh)
eval "${ssh} -- '$1'"
