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

from IM.VMRC import VMRC
from radl import radl_parse
from mock import patch, MagicMock


class TestVMRC(unittest.TestCase):
    """
    Class to test the VMRC class
    """

    @patch('IM.VMRC.Client')
    def test_search_vm(self, suds_cli):
        client = MagicMock()
        service = MagicMock()
        vmrc_res = MagicMock()
        vmrc_res.name = "Image"
        vmrc_res.hypervisor = "qemu"
        vmrc_res.userPassword = "pass"
        vmrc_res.userLogin = "user"
        vmrc_res.os = MagicMock()
        vmrc_res.os.name = "linux"
        vmrc_res.os.flavour = "ubuntu"
        vmrc_res.os.version = "14.04"
        vmrc_res.location = "one://server.com/1"
        service.search.return_value = [vmrc_res]
        client.service = service
        suds_cli.return_value = client

        vmrc = VMRC("http://host:8080/vmrc/vmrc", "user", "pass")

        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            disk.0.os.flavour='ubuntu' and
            disk.0.os.version>='12.04' and
            disk.applications contains (name = 'app' and version = '1.0') and
            soft 10 (disk.applications contains (name = 'otherapp' and version = '2.0'))
            )

            deploy test 1
            """
        radl = radl_parse.parse_radl(radl_data)

        res_radl = vmrc.search_vm(radl.systems[0])
        self.assertEqual(len(res_radl), 1)
        self.assertEqual(res_radl[0].getValue("disk.0.image.url"), "one://server.com/1")
        self.assertEqual(res_radl[0].getValue("disk.0.os.credentials.password"), "pass")
        self.assertEqual(res_radl[0].getValue("disk.0.os.credentials.username"), "user")

    @patch('IM.VMRC.Client')
    def test_list_vm(self, suds_cli):
        client = MagicMock()
        service = MagicMock()
        vmrc_res = MagicMock()
        vmrc_res.name = "Image"
        vmrc_res.hypervisor = "qemu"
        vmrc_res.userPassword = "pass"
        vmrc_res.userLogin = "user"
        vmrc_res.os = MagicMock()
        vmrc_res.os.name = "linux"
        vmrc_res.os.flavour = "ubuntu"
        vmrc_res.os.version = "14.04"
        vmrc_res.location = "one://server.com/1"
        service.list.return_value = [vmrc_res]
        client.service = service
        suds_cli.return_value = client

        vmrc = VMRC("http://host:8080/vmrc/vmrc", "user", "pass")

        res_radl = vmrc.list_vm()
        self.assertEqual(len(res_radl), 1)
        self.assertEqual(res_radl[0].getValue("disk.0.image.url"), "one://server.com/1")
        self.assertEqual(res_radl[0].getValue("disk.0.os.credentials.password"), "pass")
        self.assertEqual(res_radl[0].getValue("disk.0.os.credentials.username"), "user")

if __name__ == '__main__':
    unittest.main()
