networking-calico is part of OpenStack.  If you are planning or making a
contribution to networking-calico - for which thank you! - there is some
generic OpenStack guidance that you should be familiar with, and also some
recommended practices that are specific to networking-calico.

Guidance for all OpenStack projects
-----------------------------------

If you would like to contribute to the development of OpenStack, you must
follow the steps in this page:

   http://docs.openstack.org/infra/manual/developers.html

If you already have a good understanding of how the system works and your
OpenStack accounts are set up, you can skip to the development workflow section
of this documentation to learn how changes to OpenStack should be submitted for
review via the Gerrit tool:

   http://docs.openstack.org/infra/manual/developers.html#development-workflow

Pull requests submitted through GitHub will be ignored.


Specific guidance for networking-calico
---------------------------------------

Bugs should be filed on Launchpad, not GitHub:

   https://bugs.launchpad.net/networking-calico

When you submit a patch through Gerrit, and it passes the first set of Jenkins
checks (unit tests and PEP8), please add a comment saying 'check experimental'.
Then your patch will be further checked in a single node DevStack + Tempest
test; the results should appear in Gerrit within about an hour.

If you are proposing a significant change to the networking-calico code, please
raise and discuss it first with other Calico developers and community
participants, in either or both of two forums:

- the biweekly networking-calico IRC meeting: http://eavesdrop.openstack.org/#Networking_Calico_Meeting

- the 'openstack' channel on https://calicousers.slack.com/, for which you can
  get an invite at https://slack.projectcalico.org/.


The wider Calico project
------------------------

For guidance on contributing to the wider Calico project - i.e. to the parts of
Calico that are not specifically concerned with OpenStack integration, please
see:

   http://docs.projectcalico.org/en/latest/involved.html
