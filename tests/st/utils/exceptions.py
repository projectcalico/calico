# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
from subprocess import CalledProcessError


class CommandExecError(CalledProcessError):
    """
    Wrapper for CalledProcessError with an Exception message that gives the
    output captured from the failed command.
    """

    def __init__(self, called_process_error):
        self.called_process_error = called_process_error

    @property
    def returncode(self):
        return self.called_process_error.returncode

    @property
    def output(self):
        return self.called_process_error.output

    @property
    def cmd(self):
        return self.called_process_error.cmd

    def __str__(self):
        return "Command %s failed with RC %s and output:\n%s" % \
               (self.called_process_error.cmd,
                self.called_process_error.returncode,
                self.called_process_error.output)
