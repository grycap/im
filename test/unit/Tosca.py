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
import unittest
import sys
import yaml

sys.path.append("..")
sys.path.append(".")

from IM.VirtualMachine import VirtualMachine
from radl.radl_parse import parse_radl
from IM.InfrastructureInfo import InfrastructureInfo
from IM.tosca.Tosca import Tosca


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestTosca(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

    def test_tosca_to_radl(self):
        """Test TOSCA RADL translation"""
        tosca_data = read_file_as_string('../files/tosca_long.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl = parse_radl(str(radl))
        net = radl.get_network_by_id('public_net')
        net1 = radl.get_network_by_id('public_net_1')
        net2 = radl.get_network_by_id('private_net')
        self.assertEqual(net2.getValue('provider_id'), 'provider_id')
        self.assertIn(net.getValue('provider_id'), ['pool_name', None])
        if net.getValue('provider_id') is None:
            self.assertEqual(net1.getValue('provider_id'), 'pool_name')
            self.assertIn('1:4/tcp', net.getValue("outports"))
            self.assertIn('80/tcp-80/tcp', net.getValue("outports"))
            self.assertIn('8080/tcp-8080/tcp', net.getValue("outports"))
            self.assertEqual(net1.getValue("outports"), '8080/tcp-8080/tcp')
        else:
            self.assertEqual(net.getValue('provider_id'), 'pool_name')
            self.assertEqual(net.getValue("outports"), '8080/tcp-8080/tcp')
            self.assertIn('1:4/tcp', net1.getValue("outports"))
            self.assertIn('80/tcp-80/tcp', net1.getValue("outports"))
            self.assertIn('8080/tcp-8080/tcp', net1.getValue("outports"))

        self.assertIn('10000/tcp-10000/tcp', net2.getValue("outports"))

        lrms_wn = radl.get_system_by_name('lrms_wn')
        self.assertEqual(lrms_wn.getValue('memory.size'), 2000000000)
        lrms_server = radl.get_system_by_name('lrms_server')
        self.assertEqual(lrms_server.getValue('memory.size'), 1000000000)
        self.assertEqual(lrms_server.getValue('net_interface.0.dns_name'), 'slurmserver')
        self.assertEqual("cloudid", radl.deploys[0].cloud_id)
        self.assertEqual("cloudid", radl.deploys[1].cloud_id)
        self.assertEqual("cloudid", radl.deploys[2].cloud_id)
        other_server = radl.get_system_by_name('other_server')
        self.assertEqual(other_server.getValue("availability_zone"), 'some_zone')
        self.assertEqual(lrms_wn.getValue("disk.1.size"), 10000000000)
        self.assertEqual(lrms_wn.getValue("disk.1.type"), 'ssd')
        self.assertEqual(lrms_wn.getValue("spot"), 'no')
        self.assertEqual(lrms_wn.getValue("instance_type"), 'some_type')

        lrms_front_end_conf = radl.get_configure_by_name('lrms_front_end_conf')
        conf = yaml.safe_load(lrms_front_end_conf.recipes)[0]
        self.assertEqual(conf['vars']['front_end_ip'],
                         "{{ hostvars[groups['lrms_server'][0]]['IM_NODE_PRIVATE_IP'] }}")
        self.assertEqual(conf['vars']['wn_ips'],
                         "{{ groups['lrms_wn']|map('extract', hostvars,'IM_NODE_PRIVATE_IP')|list"
                         " if 'lrms_wn' in groups else []}}")
        self.assertEqual([d.id for d in radl.deploys][2], 'lrms_wn')

    def test_tosca_get_outputs(self):
        """Test TOSCA get_outputs function"""
        tosca_data = read_file_as_string('../files/tosca_create.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl1 = radl.clone()
        radl1.systems = [radl.get_system_by_name('web_server')]
        radl1.systems[0].setValue("net_interface.1.ip", "158.42.1.1")
        radl1.systems[0].setValue("disk.0.os.credentials.username", "ubuntu")
        radl1.systems[0].setValue("disk.0.os.credentials.password", "pass")
        inf = InfrastructureInfo()
        vm = VirtualMachine(inf, "1", None, radl1, radl1, None)
        vm.requested_radl = radl1
        inf.vm_list = [vm]
        outputs = tosca.get_outputs(inf)
        self.assertEqual(outputs, {'server_url': ['158.42.1.1'],
                                   'server_creds': {'token_type': 'password',
                                                    'token': 'pass',
                                                    'user': 'ubuntu'}})

    def test_tosca_nets_to_radl(self):
        """Test TOSCA RADL translation with nets"""
        tosca_data = read_file_as_string('../files/tosca_nets.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        print(radl)
        radl = parse_radl(str(radl))
        net = radl.get_network_by_id('pub_network')
        net1 = radl.get_network_by_id('network1')
        self.assertEqual('1194/udp-1194/udp', net.getValue("outports"))
        self.assertEqual('192.168.0.0/16,vr1_compute', net1.getValue("router"))
        self.assertEqual('yes', net1.getValue("create"))
        self.assertEqual('192.168.10.0/24', net1.getValue("cidr"))
        lrms_wn = radl.get_system_by_name("lrms_wn")
        self.assertEqual("network1", lrms_wn.getValue("net_interface.0.connection"))
        lrms_server = radl.get_system_by_name("lrms_server")
        self.assertEqual("network1", lrms_server.getValue("net_interface.0.connection"))
        self.assertEqual("pub_network", lrms_server.getValue("net_interface.1.connection"))
        self.assertEqual("slurmserver", lrms_server.getValue("net_interface.0.dns_name"))


if __name__ == "__main__":
    unittest.main()
