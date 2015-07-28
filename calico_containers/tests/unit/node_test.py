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

import unittest
from mock import patch, Mock, call
from calico_ctl.node import _attach_and_stream
from docker import Client
import sys
import signal
import os

class TestAttachAndStream(unittest.TestCase):

    @patch("calico_ctl.node.docker_client", spec=Client)
    @patch("calico_ctl.node.sys", spec=sys)
    def test_container_stops_normally(self, m_sys, m_docker_client):
        """
        Test _attach_and_stream when the container stops normally.

        :return: None
        """

        # attach(..., stream=True) returns a generator.
        def container_output_gen():
            yield ("Some output\n")
            yield ("from the container.")

        m_docker_client.attach.return_value = container_output_gen()
        m_stdout = Mock(spec=sys.stdout)
        m_sys.stdout = m_stdout
        m_container = Mock()
        _attach_and_stream(m_container)

        m_docker_client.attach.assert_called_once_with(m_container,
                                                       stream=True)
        self.assertFalse(m_container.called)
        m_stdout.write.assert_has_calls([call("Some output\n"),
                                         call("from the container.")])
        m_docker_client.stop.assert_called_once_with(m_container)

    @patch("calico_ctl.node.docker_client", spec=Client)
    @patch("calico_ctl.node.sys", spec=sys)
    def test_ctrl_c(self, m_sys, m_docker_client):
        """
        Test _attach_and_stream when a Keyboard interrupt is generated.

        :return: None
        """
        # attach(..., stream=True) returns a generator.
        def container_output_gen():
            yield ("Some output\n")
            yield ("from the container.")
            raise KeyboardInterrupt()
            yield ("This output is not printed.")

        m_docker_client.attach.return_value = container_output_gen()
        m_stdout = Mock(spec=sys.stdout)
        m_sys.stdout = m_stdout
        m_container = Mock()
        _attach_and_stream(m_container)

        m_docker_client.attach.assert_called_once_with(m_container,
                                                       stream=True)
        self.assertFalse(m_container.called)
        m_stdout.write.assert_has_calls([call("Some output\n"),
                                         call("from the container.")])
        self.assertEqual(m_stdout.write.call_count, 2)
        m_docker_client.stop.assert_called_once_with(m_container)

    @patch("calico_ctl.node.docker_client", spec=Client)
    @patch("calico_ctl.node.sys", spec=sys)
    def test_killed(self, m_sys, m_docker_client):
        """
        Test _attach_and_stream when killed by another process.

        :return: None
        """
        # attach(..., stream=True) returns a generator.
        def container_output_gen():
            yield ("Some output\n")
            yield ("from the container.")
            # Commit suicide, simulating being killed from another terminal.
            os.kill(os.getpid(), signal.SIGTERM)
            yield ("\nThis output is printed, but only because we nerf'd "
                   "sys.exit()")

        m_docker_client.attach.return_value = container_output_gen()
        m_stdout = Mock(spec=sys.stdout)
        m_sys.stdout = m_stdout
        m_container = Mock()
        _attach_and_stream(m_container)

        m_docker_client.attach.assert_called_once_with(m_container,
                                                       stream=True)
        self.assertFalse(m_container.called)
        m_sys.exit.assert_called_once_with(0)
        m_stdout.write.assert_has_calls([call("Some output\n"),
                                         call("from the container."),
                                         call("\nThis output is printed, but "
                                              "only because we nerf'd "
                                              "sys.exit()")])

        # Stop gets called twice, once for SIGTERM, and because sys.exit() gets
        # mocked, the function continues and we get another call when the
        # generator ends normally.
        m_docker_client.stop.assert_has_calls([call(m_container),
                                               call(m_container)])
        self.assertEqual(m_docker_client.stop.call_count, 2)

