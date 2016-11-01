#!/bin/bash
# Copyright (c) 2016 Tigera, Inc. All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if [ -z "$TAG" ]; then
    echo TAG environment variable must be set
    exit -1
fi

# Use "git cherry" to get a list of the commits in the development
# branch that haven't yet been merged into the Debian/Ubuntu branch.

git checkout calico_$TAG
git pull
changes=`git cherry -v ubuntu_$TAG | cut '-d ' -f 3-`

# This can be useful later when updating the debian/changelog file.

# Switch onto the Debian/Ubuntu branch and check it's up to date.

git checkout ubuntu_$TAG
git pull

# Apply and commit existing patches.

quilt push -a
git add -A .
git commit -a -m "Apply existing patches"

# Switch onto a temporary branch and merge in new changes from the
# development branch.

git checkout -b merge-tmp
git merge --no-edit calico_$TAG

# There should not be any merge conflicts here, because the files that
# should validly be changed by work on the development and packaging
# branches are in disjoint sets. But if there are, investigate and
# resolve those in the usual way, and complete the merge commit.

# Switch back to the packaging branch and use the following commands
# to tell the Debian patch system (quilt) about all the files for
# which we want to add changes into the Calico patch.

git checkout ubuntu_$TAG
grep calico.patch debian/patches/series || quilt new calico.patch
quilt add `git diff --name-only HEAD..merge-tmp`
git add -A .
git commit -a -m "Prepare for merging new changes"

# Merge in the new changes. (There can't possibly be any conflicts
# here.) And delete the temporary branch that we just merged.

git merge --no-edit merge-tmp
git branch -d merge-tmp

# Update the Calico patch so that it now incorporates all those new
# changes, as well as those that it was carrying before.

quilt refresh
git add -A .
git commit -a -m "Regenerate Calico patch"

# Unapply all the patches from the code tree - i.e. so that our (and
# other Debian/Ubuntu) patches are now reflected only in the files
# under debian/patches.

quilt pop -a
git add -A .
git rm -rf .pc
git commit -a -m "Unapply patches"

cat <<EOF

Now please add a new stanza at the top of debian/changelog to describe
the new release.

- Increment or advance the version number, in some way.

- Fill in the time and your name and email.

- Add a description of what has changed; here are the commit lines
  from "git cherry":

$changes

- For a successful PPA upload, ensure that the distribution name in
  the first line is "trusty" / "utopic" / "vivid" / etc., and not
  "unstable".

Press Enter when you're ready to commit that change.

EOF

read

# Commit that change to Git.

version=`head -1 debian/changelog | awk '{print $2;}' | sed 's/[()]//g'`
git commit -a -m "Version $version"

cat <<EOF

Does the Git history all look correct?

If so, press Enter to publish this release to GitHub.

EOF

read

git push
