.. # Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
   #
   #    Licensed under the Apache License, Version 2.0 (the "License"); you may
   #    not use this file except in compliance with the License. You may obtain
   #    a copy of the License at
   #
   #         http://www.apache.org/licenses/LICENSE-2.0
   #
   #    Unless required by applicable law or agreed to in writing, software
   #    distributed under the License is distributed on an "AS IS" BASIS,
   #    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   #    implied. See the License for the specific language governing
   #    permissions and limitations under the License.

Contribution Guidelines
=======================

Features or any changes to the codebase should be done as follows:

1. Pull latest code in the **master** branch and create a feature branch
   off this.

2. Implement your feature. Commits are cheap in Git, try to split up
   your code into many. It makes reviewing easier as well as for saner
   merging.

   -  If your commit fixes an existing issue #123, include the text "fixes
      #123" in at least one of your commit messages. This ensures the pull
      request is attached to the existing issue
      (see `How do you attach a new pull request to an existing issue on GitHub? <http://stackoverflow.com/questions/4528869/how-do-you-attach-a-new-pull-request-to-an-existing-issue-on-github>`__).

3. Push your feature branch to GitHub.  Note that before we can accept your changes,
   you need to agree to one of our contributor agreements.  See :ref:`contributor-agreements`.

4. Create a pull request using GitHub, from your branch to master.

5. Reviewer process:

   -  Receive notice of review by GitHub email, GitHub notification, or by
      checking your assigned `Project Calico GitHub
      issues <https://github.com/issues?utf8=%E2%9C%93&q=is%3Aopen+is%3Aissue+user%3Aprojectcalico>`__.
   -  Make markups as comments on the pull request (either line comments or
      top-level comments).
   -  Make a top-level comment saying something along the lines of “Fine;
      some minor comments” or “Some issues to address before merging”.
   -  If there are no issues, merge the pull request and close the branch.
      Otherwise, assign the pull request to the developer and leave this to
      them.

6. Developer process:

   -  Await review.
   -  Address code review issues on your feature branch.
   -  Push your changes to the feature branch on GitHub. This automatically
      updates the pull request.
   -  If necessary, make a top-level comment along the lines of “Please
      re-review”, assign back to the reviewer, and repeat the above.
   -  If no further review is necessary and you have the necessary
      privileges, merge the pull request and close the branch. Otherwise,
      make a top-level comment and assign back to the reviewer as above.


.. _contributor-agreements:

Contributor Agreements
----------------------
If you plan to contribute in the form of documentation or code, we need you to 
sign our Contributor License Agreement before we can accept your contribution. 
You will be prompted to do this as part of the PR process on Github.
