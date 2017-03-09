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
from multiprocessing import Queue
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import time

from IM.ansible_utils.ansible_launcher import AnsibleThread
from mock import patch, MagicMock


class TestAnsible(unittest.TestCase):
    """
    Class to test the Ansible related classes
    """

    def test_ansible_thread(self):
        result = Queue()
        tests_path = os.path.dirname(os.path.abspath(__file__))
        play_file_path = os.path.join(tests_path, "../files/play.yaml")
        inventory = os.path.join(tests_path, "../files/inventory")
        ansible_process = AnsibleThread(result, StringIO(), play_file_path, None, 1, None,
                                        "password", 1, inventory, "username")
        ansible_process.run()

        _, (return_code, _), output = result.get()
        self.assertEqual(return_code, 0)
        self.assertIn("failed=0", output.getvalue())
        self.assertIn("changed=2", output.getvalue())
        print(output.getvalue())

if __name__ == '__main__':
    unittest.main()
