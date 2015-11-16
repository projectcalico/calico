# Copyright 2015 Metaswitch Networks
#
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
FROM jeanblanchard/alpine-glibc
MAINTAINER Tom Denham <tom@projectcalico.org>

RUN apk --update add python py-setuptools iproute2 iputils ip6tables ipset

# Could make this container smaller by merging the next three lines with a remove.
RUN apk add git py-pip musl-dev gcc python-dev
ADD requirements.txt /
RUN pip install -r requirements.txt

# The test _framework_ needs to be part of the image - everything else gets volume mounted
ADD tests tests

# The container is used by mounting the code-under-test to /code
WORKDIR /code/
RUN ln -s /code/docker /usr/local/bin/docker



