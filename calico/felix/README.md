# Felix

Felix is the Calico Agent for compute hosts and similar devices. It runs on
machines that host multiple network endpoints, each behind its own logical
interface.

## Hacking on Felix

Currently, to hack on Felix you need to install it. This is to ensure that
all the Felix code lives in the correct place.

To make changes to Felix while you work, it is recommended that you use an
editable install. To do that, run:

    pip install -e .

from the root of this repository. That will cause `pip` to resolve and install
the dependencies. Once that's done, you can start Felix running by executing:

    python test.py

This loads Felix in a testing configuration, with debug logging turned on and
logging to multiple places.

Changes you make to Felix will be observed by the running code: simply re-run
`test.py` to observe your new changes.
