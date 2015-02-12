#!/bin/bash

set -e
set -x

pyinstaller calicoctl.py -a -F -s --clean
mv dist/calicoctl .
docopt-completion --manual-bash ./calicoctl.py
echo "" >>calicoctl.py.sh
echo "complete -F _calicoctlpy calicoctl" >>calicoctl.py.sh
echo "Copy calicoctl.py.sh to /etc/bash_completion.d/ to get bash completion"
