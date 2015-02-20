#!/bin/bash

set -e

if [ ! -e env/bin/activate ]
then 
  echo "Virtualenv not found, creating it."
  ./create-virtualenv.sh
fi

. env/bin/activate

pip install -r requirements.txt
rm -f calicoctl
pyinstaller calicoctl.py -a -F -s --clean
mv dist/calicoctl .

echo 
echo "Binary written to ./calicoctl"

docopt-completion --manual-bash ./calicoctl.py

# By default, the completion script expects the tool to be called
# calicoctl.py.  Add calicoctl as an alias.
echo "" >>calicoctl.py.sh
echo "complete -F _calicoctlpy calicoctl" >>calicoctl.py.sh

echo "Copy calicoctl.py.sh to /etc/bash_completion.d/ to get bash completion"
