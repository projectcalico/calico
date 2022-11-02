# Contributing Guidelines

Thanks for thinking about contributing to Project Calico! The success of an
open source project is entirely down to the efforts of its contributors, so we
do genuinely want to thank you for contributing.

This document contains some guidance and steps for contributing. Make sure you
read it thoroughly, because if you miss some of these steps we will have to ask
you to do them before we can merge it.

## Before contributing: The Contributor License Agreement

If you plan to contribute in the form of documentation or code, we need you to
sign our Contributor License Agreement before we can accept your contribution. 
You will be prompted to do this as part of the PR process on Github.

## Mailing lists and chat

A great way to talk to us, ask questions, discuss features and bounce ideas
around is to join one of the channels listed below:

* [Technical Mailing List](http://lists.projectcalico.org/mailman/listinfo/calico-tech_lists.projectcalico.org)
* [Slack Calico Users Channel](https://slack.projectcalico.org)
* IRC - [#calico](https://kiwiirc.com/client/irc.freenode.net/#calico)

## Reporting issues

Before raising an issue with *calicoctl*, please check for duplicate issues.

If you have a question, please hop on to our IRC or Slack channels (see above).

If you do need to raise an issue, please include any of the following that may
be relevant to your problem (including too much information is never
a bad thing):

-  A detailed description of the problem.
-  The steps to reproduce the problem (e.g. the full list of `calicoctl`
   commands that were run)
-  The expected result and actual result.
-  Versions of appropriate binaries and libraries.  For example, the output from
   `calicoctl version`, your version of Docker, rkt, Kubernetes etc.
-  A link to any diagnostics (e.g. if using `calicoctl`, you can gathered
   diagnostics using `calicoctl node diags` - this provides instructions for
   uploading the diags bundle to transfer.sh - or alternatively if the
   diagnostics contains sensitive information we can set up an alternative
   method for transfer).
-  If using `calicoctl` the output from `calicoctl node status` run on each node
   might also be useful.
-  Details of your OS.
-  Environment details such as GCE, bare metal, VirtualBox.

## Contributing code and documentation

For contributing code and documentation we follow the GitHub pull request
model.

-  Fork the repository on GitHub
-  Make changes to your local repository in a separate branch
-  Test the change
-  Create a pull request which will then go through a review process by one or
   more of the core team.

### Testing your changes

If you create a pull request, our automated UT and STs will be run over your
change.  We will not accept changes that do not consistently pass our automated
test suites. It is vital that our master branch be passing tests at all times.
If you tests are failing the automated tests and you don't believe they should
be, you may need to rebase your branch off the latest master.

Read the project [README](README.md) for details on running the UTs and STs.

Where possible, please add any additional tests to ensure we maintain healthy
code and feature coverage.

### Documentation

If your code change requires some documentation updates, please include these
in the pull request.

In particular changes to the `calicoctl` UX will also require changes to the
`calicoctl` documentation and possibly some of the sample guides.

### Review and merge

Assuming your code review is finished and tests are passing, your change will
then be merged as soon as possible!  Occasionally we will sit on a change, for
instance if we are planning to tag a release shortly, but this is only to
ensure the stability of the branch. After the release we will merge your change
promptly.

Before merging we prefer that you squash the commits into a single commit to
ensure we have a cleaner commit history.

### Coding style

The majority of the code is written in Go, we follow standard Go guidelines.
Be sure to run gofmt and goimport tools over the code to maintain formatting.

For code that is written in Python and we generally follow the
[PEP-8 coding style](https://www.python.org/dev/peps/pep-0008).

### Format of the commit message

The commit message should include a short subject on what changed, a body
detailing why the change was necessary, and any key points about the
implementation.

Try to keep the subject line no longer than 70 characters, and the lines of the
body no longer than 80 characters.  This improves readability in both GitHub
and when using git tools.

If the pull request fixes an issue, include a separate line in the description
with the following format:

```
Fixes #29
```

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calicoctl/CONTRIBUTING.md?pixel)](https://github.com/igrigorik/ga-beacon)
