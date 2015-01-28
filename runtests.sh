#!/bin/bash
#rm -rf env
virtualenv env
. env/bin/activate
pip install -e .
pip install nose mock coverage
nosetests --with-coverage --nocapture calico.openstack.test.test_plugin:TestPlugin
#coverage html
