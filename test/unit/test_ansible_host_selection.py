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

import os
import sys
import unittest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from IM.VirtualMachine import VirtualMachine
from radl.radl_parse import parse_radl


def _get_vm(radl_str, cloud_id):
    """
    Build a VirtualMachine object (without running __init__) with the given
    RADL and the cloud id to test the ansible host selection.
    """
    vm = VirtualMachine.__new__(VirtualMachine)
    vm.requested_radl = parse_radl(radl_str)
    vm.cloud = type("Cloud", (), {"id": cloud_id})()
    return vm


class TestAnsibleHostSelection(unittest.TestCase):

    def test_global_ansible_host(self):
        """A single global ansible host is used for any VM."""
        vm = _get_vm("""
network net ()
ansible ah1 (host = '1.1.1.1' and credentials.username = 'user' and credentials.password = 'pass')
system s (
net_interface.0.connection = 'net'
)
""", cloud_id="cloud-a")
        ah = vm.get_ansible_host()
        self.assertIsNotNone(ah)
        self.assertEqual("ah1", ah.getId())

    def test_cloud_specific_ansible_host(self):
        """The ansible host of the cloud of the VM is used."""
        vm = _get_vm("""
network net ()
ansible ah_a (host = '1.1.1.1' and cloud_id = 'cloud-a' and credentials.username = 'user'
  and credentials.password = 'pass')
ansible ah_b (host = '2.2.2.2' and cloud_id = 'cloud-b' and credentials.username = 'user'
  and credentials.password = 'pass')
system s (
net_interface.0.connection = 'net'
)
""", cloud_id="cloud-b")
        ah = vm.get_ansible_host()
        self.assertIsNotNone(ah)
        self.assertEqual("ah_b", ah.getId())

    def test_fallback_to_global_ansible_host(self):
        """If there is no host of the cloud, use the global one."""
        vm = _get_vm("""
network net ()
ansible ah_a (host = '1.1.1.1' and cloud_id = 'cloud-a' and credentials.username = 'user'
  and credentials.password = 'pass')
ansible ah_global (host = '3.3.3.3' and credentials.username = 'user'
  and credentials.password = 'pass')
system s (
net_interface.0.connection = 'net'
)
""", cloud_id="cloud-b")
        ah = vm.get_ansible_host()
        self.assertIsNotNone(ah)
        self.assertEqual("ah_global", ah.getId())

    def test_system_ansible_host_priority(self):
        """The ansible_host referenced in the system has priority over the cloud one."""
        vm = _get_vm("""
network net ()
ansible ah_a (host = '1.1.1.1' and cloud_id = 'cloud-a' and credentials.username = 'user'
  and credentials.password = 'pass')
ansible ah_b (host = '2.2.2.2' and cloud_id = 'cloud-b' and credentials.username = 'user'
  and credentials.password = 'pass')
system s (
ansible_host = 'ah_b' and
net_interface.0.connection = 'net'
)
""", cloud_id="cloud-a")
        ah = vm.get_ansible_host()
        self.assertIsNotNone(ah)
        self.assertEqual("ah_b", ah.getId())


if __name__ == "__main__":
    unittest.main()
