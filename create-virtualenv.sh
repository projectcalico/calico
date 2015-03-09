#!/bin/bash

set -e

echo "Checking dependencies..."
if { ! which pip || ! which virtualenv; }
then
  echo "Dependencies not met, please install pip, virtualenv and docker."
  exit 1
fi

rm -fr env
virtualenv env
. env/bin/activate
pip install -r requirements.txt
