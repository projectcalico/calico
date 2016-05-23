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

FROM alpine:3.3

ADD *.py /code/
ADD handlers /code/handlers

ADD build.sh /build.sh
RUN /build.sh

# Symlinks needed to workaround Alpine/Pyinstaller incompatibilties
# https://github.com/gliderlabs/docker-alpine/issues/48
RUN ln -s /lib/libc.musl-x86_64.so.1 ldd
RUN ln -s /lib /lib64
RUN ln -s /lib/ld-musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

CMD ["/dist/controller"]
