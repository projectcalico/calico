# Contributing Guidelines

Thanks for thinking about contributing to Project Calico! The success of an
open source project is entirely down to the efforts of its contributors, so we
do genuinely want to thank you for even thinking of contributing.

This document contains some guidance and steps for contributing. Make sure you
read it thoroughly, because if you miss some of these steps we will have to ask
you to do them after you make your submission, and that slows down our ability
to merge it.

## Before Contributing: The Contributor License Agreement

If you plan to contribute in the form of documentation or code, before we can
accept your contribution we need you to sign our Contributor License Agreement.
This covers the legalities, confirming that you retain ownership of your
contributions and that you are licensing them to us.

For some fairly complicated legal reasons we actually have three CLAs, and
which you sign depends on on whose behalf you are contributing:

- All individuals (except employees of the U.S. government – see below) should
  sign the [Individual Contributor License Agreement](http://www.projectcalico.org/community/Individual-Contributor-Agreement).
- If you are contributing on behalf of a company or organization, *you still
  need to sign the Individual Contributor License Agreement* as above, but
  someone at your company or organization also needs to sign the
  [Corporate Contributor License Agreement](http://www.projectcalico.org/community/corporate-contributor-agreement/)
  providing a list of people authorized to commit code to Project Calico.
- Employees of the U.S. government do not sign the Individual Contributor
  License Agreement.  Instead, someone with authority to sign on behalf of your
  agency should sign the [U.S Government Contributor License Agreement](http://www.projectcalico.org/community/us-government-contributor-agreement).

It is important to re-iterate: until you sign the required agreements we cannot
accept your contribution!

## Contributing: code and documentation

For contributing code and documentation we follow the GitHub pull request
model. This means you should fork our repository on GitHub, make your changes
in your local repository, and then open a GitHub pull request. This pull
request will then go through a review process by one or more of the core team.

Code changes will additionally be tested by our continuous integration server.
We will not accept changes that do not consistently pass our automated unit
test suite. It is vital that our master branch be passing tests at all times:
hence the restriction.

The relevant tests are our unit tests: you can run them yourself by running the
`run-unit-test.sh` script from the root of the repository.

Assuming your code review is finished and tests are passing, your change will
then be merged as soon as possible! Occasionally we will sit on a change, for
instance if we are planning to tag a release shortly, but this is only to
ensure the stability of the branch. After the release we will merge your change
promptly.
