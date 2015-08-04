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
from nose_parameterized import parameterized
from calico_ctl.bgp import *
from calico_ctl.profile import validate_arguments, profile_rule_show,\
    profile_rule_update, profile_rule_add_remove
from pycalico.datastore_datatypes import Profile, Rules, Rule


class TestProfile(unittest.TestCase):

    @parameterized.expand([
        ({'<PROFILE>':'profile-1'}, False),
        ({'<PROFILE>':'Profile!'}, True),
        ({'<SRCTAG>':'Tag-1', '<DSTTAG>':'Tag-2'}, False),
        ({'<SRCTAG>':'Tag~1', '<DSTTAG>':'Tag~2'}, True),
        ({'<SRCCIDR>':'127.a.0.1'}, True),
        ({'<DSTCIDR>':'aa:bb::zz'}, True),
        ({'<SRCCIDR>':'1.2.3.4', '<DSTCIDR>':'1.2.3.4'}, False),
        ({'<ICMPCODE>':'5'}, False),
        ({'<ICMPTYPE>':'16'}, False),
        ({'<ICMPCODE>':100, '<ICMPTYPE>':100}, False),
        ({'<ICMPCODE>':4, '<ICMPTYPE>':255}, True),
        ({}, False)
    ])
    def test_validate_arguments(self, case, sys_exit_called):
        """
        Test validate_arguments for calicoctl profile command
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            validate_arguments(case)

            # Assert that method exits on bad input
            self.assertEqual(m_sys_exit.called, sys_exit_called)

    @patch('calico_ctl.profile.client.get_profile', autospec=True)
    def test_profile_rule_show(self, m_client_get_profile):
        """
        Test for profile_rule_show function when human_readable=False
        """
        # Set up arguments
        profile_name = 'Profile_1'

        # Set up mock objects
        m_Rules = Mock(spec=Rules, id=profile_name)
        m_Profile = Mock(spec=Profile, name=profile_name, rules=m_Rules)
        m_client_get_profile.return_value = m_Profile

        # Call method under test
        profile_rule_show(profile_name, human_readable=False)

        # Assert
        m_client_get_profile.assert_called_once_with(profile_name)
        m_Profile.rules.to_json.assert_called_once_with(indent=2)

    @patch('calico_ctl.profile.client.get_profile', autospec=True)
    @patch('sys.stdout', autospec=True)
    def test_profile_rule_show_human_readable(self, m_print, m_client_get_profile):
        """
        Test for profile_rule_show function when human_readable=True
        """
        # Set up arguments
        profile_name = 'Profile_1'

        # Set up mock objects
        m_Rule = Mock(spec=Rule)
        m_Rule.pprint = Mock()
        m_Rules = Mock(spec=Rules, id=profile_name, inbound_rules=[m_Rule],
                       outbound_rules=[m_Rule])
        m_Profile = Mock(spec=Profile, name=profile_name, rules=m_Rules)
        m_client_get_profile.return_value = m_Profile

        # Call method under test
        profile_rule_show(profile_name, human_readable=True)

        # Assert
        m_client_get_profile.assert_called_once_with(profile_name)
        m_print.assert_has_calls([
            call.write('Inbound rules:'),
            call.write('\n'),
            call.write(' %3d %s' % (1, m_Rule.pprint())),
            call.write('\n'),
            call.write('Outbound rules:'),
            call.write('\n'),
            call.write(' %3d %s' % (1, m_Rule.pprint())),
            call.write('\n'),
        ])

    @patch('calico_ctl.profile.client.get_profile', autospec=True)
    def test_profile_rule_show_error_get_profile(self, m_client_get_profile):
        """
        Test for profile_rule_show function when when the client cannot get the
        specified profile

        client.get_profile raises a KeyError
        Assert that the system exits
        """
        # Set up arguments
        profile_name = 'Profile_1'

        # Set up mock objects
        m_client_get_profile.side_effect = KeyError

        # Call method under test
        self.assertRaises(SystemExit, profile_rule_show, profile_name)

        # Assert
        m_client_get_profile.assert_called_once_with(profile_name)

    @patch('calico_ctl.profile.client', autospec=True)
    @patch('sys.stdin', autospec=True)
    @patch('calico_ctl.profile.Rules', autospec=True)
    def test_profile_rule_update(self, m_Rules, m_sys_stdin, m_client):
        """
        Test for profile_rule_update function
        """
        # Set up arguments
        profile_name = 'Profile_1'

        # Set up mock objects
        m_Profile = Mock(spec=Profile, name=profile_name)
        m_client.get_profile.return_value = m_Profile
        m_sys_stdin.read.return_value = 'rules'
        m_Rules_return = Mock(spec=Rules, id=profile_name)
        m_Rules.from_json.return_value = m_Rules_return

        # Call method under test
        profile_rule_update(profile_name)

        # Assert
        m_client.get_profile.assert_called_once_with(profile_name)
        m_sys_stdin.read.assert_called_once_with()
        m_Rules.from_json.assert_called_once_with('rules')
        m_client.profile_update_rules.assert_called_once_with(m_Profile)

    @patch('calico_ctl.profile.client', autospec=True)
    @patch('sys.stdin', autospec=True)
    def test_profile_rule_update_error_get_profile(self, m_sys_stdin, m_client):
        """
        Test for profile_rule_update function when the client cannot get the
        specified profile

        client.get_profile raises a KeyError
        Assert that the system exits
        """
        # Set up mock objects
        m_client.get_profile.side_effect = KeyError

        # Call method under test expecting a SystemExit
        self.assertRaises(SystemExit, profile_rule_update, 'Profile_1')

        # Assert
        m_client.get_profile.assert_called_once_with('Profile_1')
        self.assertFalse(m_sys_stdin.called)

    @patch('calico_ctl.profile.client', autospec=True)
    @patch('sys.stdin', autospec=True)
    @patch('calico_ctl.profile.Rules', autospec=True)
    def test_profile_rule_update_no_matching_id(self, m_Rules, m_sys_stdin,
                                                m_client):
        """
        Test for profile_rule_update function when the Rules id does not match
        specified Profile name

        Assert that the system exits
        """
        # Set up mock objects
        m_Profile = Mock(spec=Profile, name='Profile_1')
        m_client.get_profile.return_value = m_Profile
        m_sys_stdin.read.return_value = 'rules'
        m_Rules_return = Mock(spec=Rules, id='Profile_2')
        m_Rules.from_json.return_value = m_Rules_return

        # Call method under test
        self.assertRaises(SystemExit, profile_rule_update, 'Profile_1')

        # Assert
        m_client.get_profile.assert_called_once_with('Profile_1')
        m_sys_stdin.read.assert_called_once_with()
        m_Rules.from_json.assert_called_once_with('rules')
        self.assertFalse(m_client.profile_update_rules.called)

    @parameterized.expand([
        ('inbound', None), ('inbound', 2), ('inbound', 5),
        ('outbound', None), ('outbound', 2), ('outbound', 5),
    ])
    def test_profile_rule_add_remove_add_rule_end_of_list(
            self, direction_arg, position_arg):
        """
        Test for profile_rule_add_remove function when adding a new Rule to a
        Profile.

        Test for both directions - inbound and outbound.

        Test for multiple positions greater than 1 or None
        (including positions out of range)
        """
        with patch('calico_ctl.profile.client', autospec=True) as m_client:
            # Setup arguments to pass to method under test
            operation = 'add'
            name = 'profile1'
            position = position_arg
            action = 'allow'
            direction = direction_arg

            # Set up Mock objects
            rule = Rule()
            m_Rules = Mock(spec=Rules, id=name, inbound_rules=[rule],
                       outbound_rules=[rule])
            m_Profile = Mock(spec=Profile, name=name, rules=m_Rules)
            m_client.get_profile.return_value = m_Profile

            # Set up new rule that function will create/add - compare in asserts
            rule_dict = {'action': 'allow', 'icmp_type':5, 'icmp_code':5}
            new_rule = Rule(**rule_dict)

            # Call method under test
            profile_rule_add_remove(operation, name, position, action, direction,
                                    icmp_type='5', icmp_code='5')

            # Assert
            m_client.get_profile.assert_called_once_with(name)
            m_client.profile_update_rules.assert_called_once_with(m_Profile)
            if direction_arg == 'inbound':
                self.assertEqual(m_Rules.inbound_rules, [rule, new_rule])
            else:
                self.assertEqual(m_Rules.outbound_rules, [rule, new_rule])

    @parameterized.expand([
        ('inbound', 0), ('inbound', 1), ('inbound', -5),
        ('outbound', 0), ('outbound', 1), ('outbound', -5),
    ])
    def test_profile_rule_add_remove_add_rule_front_of_list(
            self, direction_arg, position_arg):
        """
        Test for profile_rule_add_remove function when adding a new Rule to the
        front of the inbound or outbound rules list.

        Test for both directions - inbound and outbound.

        Test for multiple positions less than 0
        (including positions out of range)
        """
        with patch('calico_ctl.profile.client', autospec=True) as m_client:
            # Setup arguments to pass to method under test
            operation = 'add'
            name = 'profile1'
            position = position_arg
            action = 'allow'
            direction = direction_arg

            # Set up Mock objects
            rule = Rule()
            m_Rules = Mock(spec=Rules, id=name, inbound_rules=[rule],
                       outbound_rules=[rule])
            m_Profile = Mock(spec=Profile, name=name, rules=m_Rules)
            m_client.get_profile.return_value = m_Profile

            # Set up new rule that function will create/add - compare in asserts
            rule_dict = {'action': 'allow', 'icmp_type':5, 'icmp_code':5}
            new_rule = Rule(**rule_dict)

            # Call method under test
            profile_rule_add_remove(operation, name, position, action, direction,
                                    icmp_type='5', icmp_code='5')

            # Assert
            m_client.get_profile.assert_called_once_with(name)
            m_client.profile_update_rules.assert_called_once_with(m_Profile)
            if direction_arg == 'inbound':
                self.assertEqual(m_Rules.inbound_rules, [new_rule, rule])
            else:
                self.assertEqual(m_Rules.outbound_rules, [new_rule, rule])

    def test_profile_rule_add_remove_invalid_protocol(self):
        """
        Test for profile_rule_add_remove when passing a protocol (besides udp
        or tcp) and src/dst ports.

        Assert that the system exits
        """
        operation = 'add'
        name = 'profile1'
        position = None
        action = 'allow'
        direction = 'inbound'

        # Call method under test
        self.assertRaises(SystemExit, profile_rule_add_remove,
                          operation, name, position, action, direction,
                          protocol='icmp', src_ports=[40,60])

    @patch('calico_ctl.profile.client', autospec=True)
    def test_profile_rule_add_remove_fail_get_profile(self, m_client):
        """
        Test for profile_rule_add_remove when client cannot obtain a profile.

        Assert that the system exits.
        """
        # Set up mock objets
        m_client.get_profile.side_effect = KeyError

        # Setup arguments to pass to method under test
        operation = 'add'
        name = 'profile1'
        position = None
        action = 'allow'
        direction = 'inbound'

        # Call method under test
        self.assertRaises(SystemExit, profile_rule_add_remove,
                          operation, name, position, action, direction)

    @patch('calico_ctl.profile.client', autospec=True)
    def test_profile_rule_add_remove_add_rule_exists(self, m_client):
        """
        Test for profile_rule_add_remove when adding a Rule that already
        exists.

        Assert that the profile_update_rules function is not called and that
        the Rules object has not changed.
        """
        # Set up arguments to pass to method under test
        operation = 'add'
        name = 'profile1'
        position = None
        action = 'allow'
        direction = 'inbound'

        # Set up Mock objects
        rule_dict = {
            'action': 'allow'
        }
        rule = Rule(**rule_dict)
        m_Rules = Mock(spec=Rules, id=name, inbound_rules=[rule],
                       outbound_rules=[rule])
        m_Profile = Mock(spec=Profile, name=name, rules=m_Rules)
        m_client.get_profile.return_value = m_Profile

        # Call method under test
        profile_rule_add_remove(operation, name, position, action, direction)

        # Assert
        m_client.get_profile.assert_called_once_with(name)
        self.assertFalse(m_client.profile_update_rules.called)
        self.assertEqual(m_Rules.inbound_rules, [rule])
        self.assertEqual(m_Rules.outbound_rules, [rule])

    @parameterized.expand([
        ('inbound', None), ('inbound', 1), ('outbound', None), ('outbound', 1)
    ])
    def test_profile_rule_add_remove_remove_inbound(self, direction_arg,
                                                    position_arg):
        """
        Test for profile_rule_add_remove function when removing a Rule from a
        Profile.

        -  Test both direction - inbound and outbound.
        -  Test positions None and 1  (out of bounds tested elsewhere).
        """
        with patch('calico_ctl.profile.client', autospec=True) as m_client:
            # Setup arguments to pass to method under test
            operation = 'remove'
            name = 'profile1'
            position = position_arg
            action = 'allow'
            direction = direction_arg

            # Set up Mock objects
            rule_dict = {'action': 'allow'}
            rule = Rule(**rule_dict)
            m_Rules = Mock(spec=Rules, id=name, inbound_rules=[rule],
                           outbound_rules=[rule])
            m_Profile = Mock(spec=Profile, name=name, rules=m_Rules)
            m_client.get_profile.return_value = m_Profile

            # Call method under test
            profile_rule_add_remove(operation, name, position, action, direction)

            # Assert
            m_client.get_profile.assert_called_once_with(name)
            m_client.profile_update_rules.assert_called_once_with(m_Profile)
            if direction_arg == 'inbound':
                self.assertEqual(m_Rules.inbound_rules, [])
                self.assertEqual(m_Rules.outbound_rules, [rule])
            else:
                self.assertEqual(m_Rules.outbound_rules, [])
                self.assertEqual(m_Rules.inbound_rules, [rule])

    @patch('calico_ctl.profile.client', autospec=True)
    def test_profile_rule_add_remove_add_rule_not_exists(self, m_client):
        """
        Test for profile_rule_add_remove when removing a Rule that does not
        exist.

        Position is specified to be None.

        Assert that the system exits.
        """
        # Set up arguments to pass to method under test
        operation = 'remove'
        name = 'profile1'
        position = None
        action = 'allow'
        direction = 'inbound'

        # Set up Mock objects
        rule = Rule()
        m_Rules = Mock(spec=Rules, id=name, inbound_rules=[rule],
                       outbound_rules=[rule])
        m_Profile = Mock(spec=Profile, name=name, rules=m_Rules)
        m_client.get_profile.return_value = m_Profile

        # Call method under test
        self.assertRaises(SystemExit, profile_rule_add_remove,
                          operation, name, position, action, direction)

