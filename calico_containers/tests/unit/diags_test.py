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

from mock import patch, Mock, call, ANY

from sh import Command, CommandNotFound
from pycalico.datastore import DatastoreClient
from etcd import EtcdResult, EtcdException, Client

from calico_ctl import diags


class TestDiags(unittest.TestCase):

    @patch('calico_ctl.diags.tempfile', autospec=True)
    @patch('os.mkdir', autospec=True)
    @patch('os.path.isdir', autospec=True)
    @patch('calico_ctl.diags.datetime', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('socket.gethostname', autospec=True)
    @patch('sh.Command._create', spec=Command)
    @patch('calico_ctl.diags.copytree', autospec=True)
    @patch('tarfile.open', autospec=True)
    @patch('calico_ctl.diags.DatastoreClient', autospec=True)
    @patch('calico_ctl.diags.upload_temp_diags', autospec=True)
    @patch('calico_ctl.diags.subprocess', autospec=True)
    def test_save_diags(self, m_subprocess, m_upload_temp_diags,
                        m_DatastoreClient, m_tarfile_open, m_copytree,
                        m_sh_command, m_socket, m_open, m_datetime,
                        os_path_isdir, m_os_mkdir, m_tempfile):
        """
        Test save_diags for calicoctl diags command
        """
        # Set up mock objects
        m_tempfile.mkdtemp.return_value = '/temp/dir'
        date_today = '2015-7-24_09_05_00'
        m_datetime.strftime.return_value = date_today
        m_socket.return_value = 'hostname'
        m_sh_command_return = Mock(autospec=True)
        m_sh_command.return_value = m_sh_command_return
        m_datetime.today.return_value = 'diags-07242015_090500.tar.gz'
        m_os_mkdir.return_value = True
        # The DatastoreClient contains an etcd Client
        # The etcd Client reads in a list of children of type EtcdResult
        # The children are accessed by calling get_subtree method on the etcd Client
        m_datastore_client = Mock(spec=DatastoreClient)
        m_datastore_client.etcd_client = Mock(spec=Client)
        m_datastore_data = Mock(spec=EtcdResult)
        m_child_1 = EtcdResult(node={'dir': True, 'key': 666})
        m_child_2 = EtcdResult(node={'key': 555, 'value': 999})
        m_datastore_data.get_subtree.return_value = [m_child_1, m_child_2]
        m_datastore_client.etcd_client.read.return_value = m_datastore_data
        m_DatastoreClient.return_value = m_datastore_client

        # Set up arguments
        log_dir = '/log/dir'
        temp_dir = '/temp/dir/'
        diags_dir = temp_dir + 'diagnostics'

        # Call method under test
        diags.save_diags(log_dir, upload=True)

        # Assert
        m_subprocess.call.assert_called_once_with(
            ["docker", "exec", "calico-node", "pkill", "-SIGUSR1", "felix"])
        m_tempfile.mkdtemp.assert_called_once_with()
        m_os_mkdir.assert_called_once_with(diags_dir)
        m_open.assert_has_calls([
            call(diags_dir + '/date', 'w'),
            call().__enter__().write('DATE=%s' % date_today),
            call(diags_dir + '/hostname', 'w'),
            call().__enter__().write('hostname'),
            call(diags_dir + '/netstat', 'w'),
            call().__enter__().writelines(m_sh_command_return()),
            call(diags_dir + '/route', 'w'),
            call().__enter__().write('route --numeric\n'),
            call().__enter__().writelines(m_sh_command_return()),
            call().__enter__().write('ip route\n'),
            call().__enter__().writelines(m_sh_command_return()),
            call().__enter__().write('ip -6 route\n'),
            call().__enter__().writelines(m_sh_command_return()),
            call(diags_dir + '/iptables', 'w'),
            call().__enter__().writelines(m_sh_command_return()),
            call(diags_dir + '/ipset', 'w'),
            call().__enter__().writelines(m_sh_command_return()),
            call(diags_dir + '/etcd_calico', 'w'),
            call().__enter__().write('dir?, key, value\n'),
            call().__enter__().write('DIR,  666,\n'),
            call().__enter__().write('FILE, 555, 999\n')
        ], any_order=True)
        m_sh_command.assert_has_calls([
            call('netstat'),
            call()(all=True, numeric=True),
            call('route'),
            call()(numeric=True),
            call('ip'),
            call()('route'),
            call()('-6', 'route'),
            call('iptables-save'),
            call()(),
            call('ipset'),
            call()('list')
        ])
        m_datastore_client.etcd_client.read.assert_called_once_with('/calico', recursive=True)
        m_copytree.assert_called_once_with(log_dir, diags_dir + '/logs', ignore=ANY)
        m_tarfile_open.assert_called_once_with(temp_dir + date_today, 'w:gz')
        m_upload_temp_diags.assert_called_once_with(temp_dir + date_today)

    @patch('calico_ctl.diags.tempfile', autospec=True)
    @patch('os.mkdir', autospec=True)
    @patch('os.path.isdir', autospec=True)
    @patch('calico_ctl.diags.datetime', autospec=True)
    @patch('__builtin__.open', autospec=True)
    @patch('socket.gethostname', autospec=True)
    @patch('sh.Command._create', spec=Command)
    @patch('calico_ctl.diags.copytree', autospec=True)
    @patch('tarfile.open', autospec=True)
    @patch('calico_ctl.diags.DatastoreClient', autospec=True)
    @patch('calico_ctl.diags.subprocess', autospec=True)
    def test_save_diags_exceptions(
            self, m_subprocess, m_DatastoreClient, m_tarfile_open, m_copytree,
            m_sh_command, m_socket, m_open, m_datetime, m_os_path_isdir,
            m_os_mkdir, m_tempfile):
        """
        Test all exception cases save_diags method in calicoctl diags command

        Raise CommandNotFound when sh.Command._create is called
        Raise EtcdException when trying to read from the etcd datastore
        Return false when trying to read logs from log directory
        """
        # Set up mock objects
        m_tempfile.mkdtemp.return_value = '/temp/dir'
        date_today = '2015-7-24_09_05_00'
        m_datetime.strftime.return_value = date_today
        m_socket.return_value = 'hostname'
        m_sh_command_return = Mock(autospec=True)
        m_sh_command.return_value = m_sh_command_return
        m_sh_command.side_effect= CommandNotFound
        m_os_path_isdir.return_value = False
        m_datastore_client = Mock(spec=DatastoreClient)
        m_datastore_client.etcd_client = Mock(spec=Client)
        m_datastore_client.etcd_client.read.side_effect = EtcdException
        m_DatastoreClient.return_value = m_datastore_client

        # Set up arguments
        log_dir = '/log/dir'
        temp_dir = '/temp/dir/'
        diags_dir = temp_dir + 'diagnostics'

        # Call method under test
        diags.save_diags(log_dir, upload=False)

        # Assert
        m_subprocess.call.assert_called_once_with(
            ["docker", "exec", "calico-node", "pkill", "-SIGUSR1", "felix"])
        m_open.assert_has_calls([
            call(diags_dir + '/date', 'w'),
            call().__enter__().write('DATE=%s' % date_today),
            call(diags_dir + '/hostname', 'w'),
            call().__enter__().write('hostname'),
            call(diags_dir + '/netstat', 'w'),
            call(diags_dir + '/route', 'w'),
            call(diags_dir + '/iptables', 'w'),
            call(diags_dir + '/ipset', 'w'),
        ], any_order=True)
        self.assertNotIn([
            call().__enter__().writelines(m_sh_command_return()),
            call().__enter__().write('route --numeric\n'),
            call().__enter__().writelines(m_sh_command_return()),
            call().__enter__().write('ip route\n'),
            call().__enter__().writelines(m_sh_command_return()),
            call().__enter__().write('ip -6 route\n'),
            call().__enter__().writelines(m_sh_command_return()),
            call().__enter__().writelines(m_sh_command_return()),
            call().__enter__().writelines(m_sh_command_return()),
            call(diags_dir + '/etcd_calico', 'w'),
            call().__enter__().write('dir?, key, value\n'),
            call().__enter__().write('DIR,  666,\n'),
            call().__enter__().write('FILE, 555, 999\n')
        ], m_open.mock_calls)
        self.assertFalse(m_copytree.called)
        m_tarfile_open.assert_called_once_with(temp_dir + date_today, 'w:gz')

