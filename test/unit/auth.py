#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import os
import shutil

from IM.auth import Authentication


class TestAuth(unittest.TestCase):
    """
    Class to test the Authentication class
    """

    def test_auth_read(self):
        auth_lines = ["""id = 1; type = InfrastructureManager; username = someuser; password = somepass """,
                      """id = 2; type = VMRC; username = someuser; password = somepass; """,
                      """id = 3; type = OpenNebula; username = someuser; password = "some;'pass" """,
                      """id = 4; type = EC2; username = someuser; password = 'some;"pass' """]
        auth = Authentication.read_auth_data(auth_lines)
        self.assertEqual(auth, [{'id': '1', 'password': "somepass",
                                 'type': 'InfrastructureManager', 'username': 'someuser'},
                                {'id': '2', 'password': "somepass",
                                 'type': 'VMRC', 'username': 'someuser'},
                                {'id': '3', 'password': "some;'pass",
                                 'type': 'OpenNebula', 'username': 'someuser'},
                                {'id': '4', 'password': 'some;"pass',
                                 'type': 'EC2', 'username': 'someuser'}])

        tests_path = os.path.dirname(os.path.abspath(__file__))
        shutil.copyfile(os.path.join(tests_path, "../files/privatekey.pem"), "/tmp/privatekey.pem")
        auth = Authentication(Authentication.read_auth_data(os.path.join(tests_path, "../files/auth.dat")))
        auth_data = auth.getAuthInfoByID("occi")
        self.assertEqual(auth_data[0]['proxy'][:37], "-----BEGIN RSA PRIVATE KEY-----\nMIIEo")
        os.unlink("/tmp/privatekey.pem")

    def test_get_auth(self):
        auth_lines = ["""id = 1; type = InfrastructureManager; username = someuser; password = somepass """,
                      """id = 2; type = VMRC; username = someuser; password = somepass; """]
        auth = Authentication(Authentication.read_auth_data(auth_lines))
        auth_data = auth.getAuthInfoByID("1")
        self.assertEqual(auth_data, [{'id': '1', 'password': "somepass",
                                      'type': 'InfrastructureManager', 'username': 'someuser'}])
        auth_data = auth.getAuthInfo("VMRC")
        self.assertEqual(auth_data, [{'id': '2', 'password': "somepass",
                                      'type': 'VMRC', 'username': 'someuser'}])


if __name__ == '__main__':
    unittest.main()
