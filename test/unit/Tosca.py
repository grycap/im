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
import json

from mock import MagicMock

sys.path.append("..")
sys.path.append(".")

from IM.VirtualMachine import VirtualMachine
from radl.radl_parse import parse_radl
from radl.radl import system, Feature
from IM.InfrastructureInfo import InfrastructureInfo
from IM.tosca.Tosca import Tosca


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    with open(abs_file_path, 'r') as f:
        return f.read()


class TestTosca(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

    def test_tosca_to_radl(self):
        """Test TOSCA RADL translation"""
        tosca_data = read_file_as_string('../files/tosca_long.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl.check()
        radl = parse_radl(str(radl))
        self.assertEqual(radl.description.getValue("name"), "Some Infra Name")
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

        self.assertIn('0.0.0.0/0-10000/tcp-10000/tcp', net2.getValue("outports"))
        self.assertIn('8.0.0.0/24-80/tcp-80/tcp', net2.getValue("outports"))

        lrms_wn = radl.get_system_by_name('lrms_wn')
        self.assertEqual(lrms_wn.getValue('memory.size'), 2000000000)
        self.assertEqual(lrms_wn.getValue('cpu.arch'), 'x86_64')
        lrms_server = radl.get_system_by_name('lrms_server')
        self.assertEqual(lrms_server.getValue('instance_name'), 'myslurmserver')
        self.assertEqual(lrms_server.getValue('memory.size'), 1000000000)
        self.assertEqual(lrms_server.getValue('net_interface.0.dns_name'), 'slurmserver')
        self.assertEqual(lrms_server.getValue('net_interface.1.additional_dns_names'), ['test.some.com'])
        if lrms_server.getValue("disk.1.size") == 10000000000:
            self.assertEqual(lrms_server.getValue("disk.1.mount_path"), "/mnt/disk2")
        else:
            self.assertEqual(lrms_server.getValue("disk.1.size"), 20000000000)
            self.assertEqual(lrms_server.getValue("disk.1.mount_path"), "/mnt/disk3")
        if lrms_server.getValue("disk.2.size") == 10000000000:
            self.assertEqual(lrms_server.getValue("disk.2.mount_path"), "/mnt/disk2")
        else:
            self.assertEqual(lrms_server.getValue("disk.2.size"), 20000000000)
            self.assertEqual(lrms_server.getValue("disk.2.mount_path"), "/mnt/disk3")

        self.assertEqual("cloudid", radl.deploys[0].cloud_id)
        self.assertEqual("cloudid", radl.deploys[1].cloud_id)
        self.assertEqual("cloudid", radl.deploys[2].cloud_id)
        other_server = radl.get_system_by_name('other_server')
        self.assertEqual(other_server.getValue("availability_zone"), 'some_zone')
        self.assertEqual(lrms_wn.getValue("disk.1.size"), 10000000000)
        self.assertEqual(lrms_wn.getValue("disk.1.type"), 'ssd')
        self.assertEqual(lrms_wn.getValue("spot"), 'no')
        self.assertEqual(lrms_wn.getValue("instance_type"), 'some_type')

        lrms_front_end_conf = radl.get_configure_by_name('lrms_front_end_lrms_server_conf')
        conf = yaml.safe_load(lrms_front_end_conf.recipes)[0]
        self.assertEqual(conf['vars']['front_end_ip'],
                         "{{ hostvars[groups['lrms_server'][0]]['IM_NODE_PRIVATE_IP'] }}")
        self.assertEqual(conf['vars']['wn_ips'],
                         "{{ groups['lrms_wn']|map('extract', hostvars,'IM_NODE_PRIVATE_IP')|list"
                         " if 'lrms_wn' in groups else []}}")
        self.assertEqual([d.id for d in radl.deploys][2], 'lrms_wn')
        att_conf = radl.get_configure_by_name('lrms_server_tosca.relationships.indigo.onedatastorage.attachesto_conf')
        conf = yaml.safe_load(att_conf.recipes)[0]

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
        vm.cont_out = read_file_as_string('../files/vm_cont_out.txt')
        inf.vm_list = [vm]
        outputs = tosca.get_outputs(inf)
        self.assertEqual(outputs, {'server_url': ['158.42.1.1'],
                                   'server_creds': {'token_type': 'password',
                                                    'token': 'pass',
                                                    'user': 'ubuntu'},
                                   'server_creds_password': 'pass',
                                   'ansible_output': 'Install user requested apps'})

    def test_tosca_nets_to_radl(self):
        """Test TOSCA RADL translation with nets"""
        tosca_data = read_file_as_string('../files/tosca_nets.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl = parse_radl(str(radl))
        net = radl.get_network_by_id('pub_network')
        net1 = radl.get_network_by_id('network1')
        self.assertEqual('10.0.1.0/24-1194/udp-1194/udp', net.getValue("outports"))
        self.assertEqual('192.168.0.0/16,vr1_compute', net1.getValue("router"))
        self.assertEqual('yes', net1.getValue("create"))
        self.assertEqual('192.168.10.0/24', net1.getValue("cidr"))
        self.assertEqual('username@proxy.host.com', net1.getValue("proxy_host"))
        proxy_key = """-----BEGIN RSA PRIVATE KEY-----\naaa\n-----END RSA PRIVATE KEY-----\n"""
        self.assertEqual(proxy_key, net1.getValue("proxy_key"))
        lrms_wn = radl.get_system_by_name("lrms_wn")
        self.assertEqual("network1", lrms_wn.getValue("net_interface.0.connection"))
        lrms_server = radl.get_system_by_name("lrms_server")
        self.assertEqual("network1", lrms_server.getValue("net_interface.0.connection"))
        self.assertEqual("pub_network", lrms_server.getValue("net_interface.1.connection"))
        self.assertEqual("slurmserver", lrms_server.getValue("net_interface.0.dns_name"))

    def test_merge_yaml(self):
        """Test TOSCA merge two yamls"""
        a = {"wn_port": {"requirements": [{"binding": "lrms_wn"}, {"link": "network1"}]}}
        b = {"wn_port": {"requirements": [{"binding": "lrms_wn"}, {"link": "network2"}]}}
        c = Tosca._merge_yaml(a, b)
        self.assertEqual(c, b)

        a = {"requirements": [{"binding": "lrms_wn"}, {"link": "network1"}]}
        b = {"requirements": [{"binding": "lrms_wn"}, {"link": "network2"}, {"other": "value"}]}
        c = Tosca._merge_yaml(a, b)
        self.assertEqual(c, b)

    def test_tosca_add_hybrid1(self):
        tosca_data = read_file_as_string('../files/tosca_add_hybrid_l2.yml')
        tosca = Tosca(tosca_data)
        inf_info = MagicMock()
        vm1 = MagicMock()
        system1 = system("lrms_server", [Feature("disk.0.image.url", "=", "ost://cloud1.com/image1"),
                                         Feature("net_interface.0.connection", "=", "network1")])
        vm1.info.systems = [system1]
        vm2 = MagicMock()
        system2 = system("lrms_wn", [Feature("disk.0.image.url", "=", "ost://cloud1.com/image1"),
                                     Feature("net_interface.0.connection", "=", "network1")])
        vm2.info.systems = [system2]
        inf_info.get_vm_list_by_system_name.return_value = {"lrms_server": [vm1], "lrms_wn": [vm2]}
        _, radl = tosca.to_radl(inf_info)
        radl = parse_radl(str(radl))
        lrms_wn = radl.get_system_by_name("lrms_wn")
        self.assertEqual("network2", lrms_wn.getValue("net_interface.0.connection"))

    def test_tosca_add_hybrid2(self):
        tosca_data = read_file_as_string('../files/tosca_add_hybrid.yml')
        tosca = Tosca(tosca_data)
        inf_info = MagicMock()
        vm1 = MagicMock()
        system1 = system("lrms_server", [Feature("disk.0.image.url", "=", "ost://cloud1.com/image1"),
                                         Feature("net_interface.0.connection", "=", "private_net")])
        vm1.info.systems = [system1]
        vm2 = MagicMock()
        system2 = system("lrms_wn", [Feature("disk.0.image.url", "=", "ost://cloud3.com/image1"),
                                     Feature("net_interface.0.connection", "=", "private.cloud3.com")])
        vm2.info.systems = [system2]
        inf_info.get_vm_list_by_system_name.return_value = {"lrms_server": [vm1], "lrms_wn": [vm2]}
        net = MagicMock()
        net.isPublic.return_value = False
        inf_info.radl.get_network_by_id.return_value = net
        _, radl = tosca.to_radl(inf_info)
        radl = parse_radl(str(radl))
        lrms_wn = radl.get_system_by_name("lrms_wn")
        self.assertEqual("private.cloud2.com", lrms_wn.getValue("net_interface.0.connection"))

    def test_tosca_param_get_att(self):
        tosca_data = read_file_as_string('../files/tosca_param_get_att.yml')
        tosca = Tosca(tosca_data)
        inf_info = MagicMock()
        vm1 = MagicMock()
        vm1.getPublicIP.return_value = "8.8.8.8"
        system1 = system("server", [Feature("disk.0.image.url", "=", "ost://cloud1.com/image1"),
                                    Feature("net_interface.0.connection", "=", "public")])
        vm1.info.systems = [system1]
        inf_info.get_vm_list_by_system_name.return_value = {"server": [vm1]}
        _, radl = tosca.to_radl(inf_info)
        print(radl)
        conf = None
        for elem in radl.configures:
            if elem.name == "test_server_conf":
                conf = elem
        conf = yaml.safe_load(conf.recipes)[0]
        print(str(radl))
        self.assertEqual(conf['vars']['wn_ips'], ["{{ hostvars[groups['server'][0]]['IM_NODE_PUBLIC_IP'] }}"])

    def test_tosca_compute_tags(self):
        """Test TOSCA RADL translation with Compute tags"""
        tosca_data = read_file_as_string('../files/tosca_tags.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl = parse_radl(str(radl))
        node = radl.get_system_by_name('node')
        self.assertIn('tag1=value1', node.getValue("instance_tags"))
        self.assertIn('tag2=value2', node.getValue("instance_tags"))

    def test_tosca_ansible_host(self):
        """Test TOSCA RADL translation with an Ansible host"""
        tosca_data = read_file_as_string('../files/tosca_ansible_host.yaml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl = parse_radl(str(radl))
        ansible = radl.ansible_hosts[0]
        self.assertEqual('ansible_host_ip_or_name', ansible.getValue("host"))
        self.assertEqual('username', ansible.getValue("credentials.username"))
        self.assertEqual('password', ansible.getValue("credentials.password"))
        node = radl.get_system_by_name('simple_node')
        self.assertEqual('deployed_node_ip', node.getValue("net_interface.0.ip"))
        self.assertEqual('password', node.getValue("disk.0.os.credentials.password"))
        self.assertEqual('username', node.getValue("disk.0.os.credentials.username"))

    def test_tosca_oscar(self):
        """Test TOSCA RADL translation with OSCAR functions"""
        tosca_data = read_file_as_string('../files/tosca_oscar_host.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl = parse_radl(str(radl))
        radl.check()
        node = radl.get_configure_by_name('oscar_plants')
        epected_res = """
  - tasks:
    - include_tasks: utils/tasks/oscar_function.yml
      vars:
        oscar_endpoint: "https://cluster.oscar.com"
        oscar_username: "oscar"
        oscar_password: "oscar_password"
"""
        self.assertIn(epected_res, node.recipes)
        conf = yaml.safe_load(node.recipes)
        service_json = json.loads(conf[0]["tasks"][0]["vars"]["oscar_service_json"])
        expected_json = {'alpine': False,
                         'cpu': "0.5",
                         "enable_gpu": False,
                         'image': 'grycap/image',
                         'input': [{'path': 'input', 'storage_provider': 'minio.default'}],
                         'memory': '488Mi',
                         'name': 'plants',
                         'output': [{'path': 'output', 'storage_provider': 'minio.default'}],
                         'script': '#!/bin/bash\necho "Hola"\n',
                         'storage_providers': {'onedata': {'my_onedata': {'oneprovider_host': 'my_provider.com',
                                                                          'token': 'my_very_secret_token',
                                                                          'space': 'my_onedata_space'}}}}
        self.assertEqual(service_json, expected_json)

        tosca_data = read_file_as_string('../files/tosca_oscar.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl = parse_radl(str(radl))
        radl.check()
        node = radl.get_system_by_name('plants')
        self.assertEqual(node.getValue("disk.0.image.url"), "grycap/image")
        self.assertEqual(node.getValue("script"), '#!/bin/bash\necho "Hola"\n')
        self.assertEqual(node.getValue("memory.size"), 512000000)
        self.assertEqual(node.getValue("alpine"), 0)
        self.assertEqual(node.getValue("gpu.count"), 1)
        self.assertEqual(node.getValue("cpu.sgx"), 1)
        self.assertEqual(node.getValue("input.0.path"), 'input')
        self.assertEqual(node.getValue("output.0.path"), 'output')
        self.assertEqual(node.getValue("onedata.0.id"), 'my_onedata')
        self.assertEqual(node.getValue("onedata.0.oneprovider_host"), 'my_provider.com')
        conf = radl.get_configure_by_name('plants')
        self.assertEqual(conf.recipes, None)
        self.assertEqual(radl.deploys[0].id, "plants")
        self.assertEqual(radl.deploys[0].vm_number, 1)

    def test_tosca_oscar_get_attribute(self):
        """Test TOSCA OSCAR get_attributes function"""
        tosca_data = read_file_as_string('../files/tosca_oscar.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl1 = radl.clone()
        radl1.systems = [radl.get_system_by_name('plants')]
        inf = InfrastructureInfo()

        cloud_info = MagicMock(["getCloudConnector", "get_url"])
        cloud_con = MagicMock(["cloud", "auth", "type"])
        cloud_con.type = "OSCAR"
        cloud_con.cloud = cloud_info
        cloud_con.auth = {"username": "oscar_user", "password": "oscar_pass"}
        cloud_info.getCloudConnector.return_value = cloud_con
        cloud_info.get_url.return_value = "http://oscar.endpoint.com"

        vm = VirtualMachine(inf, "1", cloud_info, radl1, radl1, None)
        vm.requested_radl = radl1
        inf.vm_list = [vm]
        outputs = tosca.get_outputs(inf)
        self.assertEqual(outputs, {'oscar_service_url': 'http://oscar.endpoint.com',
                                   'oscar_service_cred': {'token': 'oscar_pass',
                                                          'token_type': 'password',
                                                          'user': 'oscar_user'}})

        tosca_data = read_file_as_string('../files/tosca_oscar_host.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl1 = radl.clone()
        inf = InfrastructureInfo()

        vm = VirtualMachine(inf, "1", cloud_info, radl1, radl1, None)
        vm.requested_radl = radl1
        inf.vm_list = [vm]
        outputs = tosca.get_outputs(inf)
        self.assertEqual(outputs, {'oscar_service_url': 'https://cluster.oscar.com',
                                   'oscar_service_cred': {'token': 'oscar_password',
                                                          'token_type': 'password',
                                                          'user': 'oscar'}})

    def test_tosca_oscar_delete(self):
        """Test TOSCA RADL deletion with OSCAR functions"""
        tosca_data = read_file_as_string('../files/tosca_oscar_host.yml')
        tosca_yaml = yaml.safe_load(tosca_data)
        tosca_yaml["topology_template"]["node_templates"]["plants"]["capabilities"] = \
            {"scalable": {"properties": {"count": 0}}}
        tosca_data = yaml.safe_dump(tosca_yaml)

        tosca = Tosca(tosca_data)
        remove_list, radl = tosca.to_radl()
        self.assertEqual(remove_list, [])
        radl = parse_radl(str(radl))
        radl.check()
        node = radl.get_configure_by_name('oscar_plants')
        epected_res = """
  - tasks:
    - include_tasks: utils/tasks/del_oscar_function.yml
      vars:
        oscar_endpoint: "https://cluster.oscar.com"
        oscar_username: "oscar"
        oscar_password: "oscar_password"
        oscar_service_name: 'plants'
"""
        self.assertIn(epected_res, node.recipes)

        tosca_data = read_file_as_string('../files/tosca_oscar.yml')
        tosca_yaml = yaml.safe_load(tosca_data)
        tosca_yaml["topology_template"]["node_templates"]["plants"]["capabilities"] = \
            {"scalable": {"properties": {"count": 0}}}
        tosca_data = yaml.safe_dump(tosca_yaml)

        vm1 = MagicMock()
        system1 = system("plants", [Feature("disk.0.image.url", "=", "grycap/image")])
        vm1.info.systems = [system1]
        vm1.creation_date = 1
        vm1.im_id = 1
        inf_info = MagicMock()
        inf_info.get_vm_list_by_system_name.return_value = {"plants": [vm1]}

        tosca = Tosca(tosca_data)
        remove_list, radl = tosca.to_radl(inf_info)
        self.assertEqual(remove_list, [1])
        radl = parse_radl(str(radl))
        radl.check()

    def test_tosca_remove(self):
        tosca_data = read_file_as_string('../files/tosca_remove_no_list.yml')
        tosca = Tosca(tosca_data)
        inf_info = MagicMock()
        vm1 = MagicMock()
        system1 = system("web_server", [Feature("disk.0.image.url", "=", "ost://cloud1.com/image1"),
                                        Feature("net_interface.0.connection", "=", "network1")])
        vm1.info.systems = [system1]
        vm1.creation_date = 0
        vm1.im_id = 0
        vm2 = MagicMock()
        system2 = system("db_server", [Feature("disk.0.image.url", "=", "ost://cloud1.com/image1"),
                                       Feature("net_interface.0.connection", "=", "network1")])
        vm2.info.systems = [system2]
        vm2.creation_date = 1
        vm2.im_id = 1
        vm3 = MagicMock()
        system3 = system("db_server", [Feature("disk.0.image.url", "=", "ost://cloud1.com/image1"),
                                       Feature("net_interface.0.connection", "=", "network1")])
        vm3.info.systems = [system3]
        vm3.creation_date = 2
        vm3.im_id = 2
        inf_info.get_vm_list_by_system_name.return_value = {"web_server": [vm1], "db_server": [vm2, vm3]}
        remove_list, _ = tosca.to_radl(inf_info)
        self.assertEqual(remove_list, [1])

        tosca_data = read_file_as_string('../files/tosca_remove.yml')
        tosca = Tosca(tosca_data)
        remove_list, _ = tosca.to_radl(inf_info)
        self.assertEqual(remove_list, [2])

    def test_tosca_k8s(self):
        """Test TOSCA RADL translation with Containers for K8s"""
        tosca_data = read_file_as_string('../files/tosca_k8s.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl = parse_radl(str(radl))
        radl.check()

        self.assertEqual(radl.description.getValue("namespace"), "somenamespace")
        node = radl.get_system_by_name('mysql-container-%s' % tosca.id[0:8])
        self.assertEqual(node.getValue("disk.0.image.url"), "docker://docker.io/mysql:8")
        self.assertEqual(node.getValue("cpu.count"), 0.5)
        self.assertEqual(node.getValue("memory.size"), 1000000000)
        self.assertEqual(node.getValue("disk.1.size"), 10000000000)
        self.assertEqual(node.getValue("disk.1.mount_path"), '/var/lib/mysql')
        self.assertEqual(node.getValue("environment.variables"),
                         'MYSQL_ROOT_PASSWORD=my-secret,MYSQL_DATABASE=im-db,TEST="some,value"')
        self.assertEqual(node.getValue("net_interface.0.connection"), 'mysql-container-%s_priv' % tosca.id[0:8])
        self.assertIsNone(node.getValue("net_interface.1.connection"))
        net = radl.get_network_by_id('mysql-container-%s_priv' % tosca.id[0:8])
        self.assertEqual(net.getValue("outports"), '3306/tcp-3306/tcp')
        self.assertEqual(net.getValue("outbound"), 'no')
        conf = radl.get_configure_by_name('mysql-container-%s' % tosca.id[0:8])
        self.assertEqual(conf.recipes, None)

        node = radl.get_system_by_name('im-container-%s' % tosca.id[0:8])
        self.assertEqual(node.getValue("disk.0.image.url"), "docker://grycap/im")
        self.assertEqual(node.getValue("command"), ["/bin/sh", "-c", "im_service.py"])
        net = radl.get_network_by_id('im-container-%s_pub' % tosca.id[0:8])
        self.assertEqual(net.getValue("outports"), '30880/tcp-8800/tcp')
        self.assertEqual(net.getValue("outbound"), 'yes')
        self.assertEqual(node.getValue("disk.1.content"), '[im]\nREST_API = True')
        self.assertEqual(node.getValue("disk.1.mount_path"), '/etc/im/im.cfg')
        self.assertEqual(node.getValue("disk.2.content"), 'c29tZSBlbmNvZGVkIGNvbnRlbnQ=')
        self.assertEqual(node.getValue("disk.2.mount_path"), '/etc/secret')
        self.assertEqual(node.getValue("environment.variables"),
                         'IM_DATA_DB=mysql://root:my-secret@mysql-container-%s:3306/im-db' % tosca.id[0:8])
        self.assertEqual(node.getValue("net_interface.0.connection"), 'im-container-%s_pub' % tosca.id[0:8])
        self.assertIsNone(node.getValue("net_interface.1.connection"))
        self.assertEqual(node.getValue("net_interface.0.dns_name"), 'https://im.domain.com/im')
        conf = radl.get_configure_by_name('im-container-%s' % tosca.id[0:8])
        self.assertEqual(conf.recipes, None)

    def test_tosca_k8s_get_attribute(self):
        """Test TOSCA K8s get_attributes function"""
        tosca_data = read_file_as_string('../files/tosca_k8s.yml')
        tosca = Tosca(tosca_data)
        _, radl = tosca.to_radl()
        radl1 = radl.clone()
        radl1.systems = [radl.get_system_by_name('im-container-%s' % tosca.id[0:8])]
        inf = InfrastructureInfo()
        radl1.systems[0].setValue("net_interface.0.ip", "8.8.8.8")

        radl2 = radl.clone()
        radl2.systems = [radl.get_system_by_name('mysql-container-%s' % tosca.id[0:8])]

        cloud_info = MagicMock()
        vm = VirtualMachine(inf, "1", cloud_info, radl1, radl1, None)
        vm2 = VirtualMachine(inf, "2", cloud_info, radl2, radl2, None)
        vm.requested_radl = radl1
        vm2.requested_radl = radl2
        inf.vm_list = [vm, vm2]
        outputs = tosca.get_outputs(inf)
        self.assertEqual(outputs, {'im_service_endpoint': 'https://im.domain.com/im',
                                   'mysql_service_endpoint': 'mysql-container-%s:3306' % tosca.id[0:8]})

    def test_tosca_repo(self):
        """Test TOSCA RADL translation with Compute tags"""
        tosca_data = read_file_as_string('../files/tosca_repo.yml')
        tosca = Tosca(tosca_data, tosca_repo="https://raw.githubusercontent.com/grycap/tosca/main/templates/")
        _, radl = tosca.to_radl()
        radl = parse_radl(str(radl))
        node = radl.get_system_by_name('simple_node')
        self.assertEqual(node.getValue("cpu.count"), 16)
        self.assertEqual(node.getValue("gpu.count"), 1)

        with self.assertRaises(Exception) as ex:
            tosca = Tosca(tosca_data)
        expected_error = 'Error parsing TOSCA template: Relative file name "simple-node-disk.yml"' \
                         ' cannot be used in a pre-parsed input template.'
        self.assertEqual(expected_error, str(ex.exception))

        with self.assertRaises(Exception) as ex:
            tosca = Tosca(tosca_data, tosca_repo="https://raw.githubusercontent.com/grycap/tosca/eosc_dc/templates/")
        expected_error = "Error parsing TOSCA template: Failed to reach server " \
                         '"https://raw.githubusercontent.com/grycap/tosca/eosc_dc/templates/simple-node-disk.yml". ' \
                         "Reason is: Not Found."
        self.assertEqual(expected_error, str(ex.exception))

        # Test with a full URL in the template_file and not in the repo
        tosca_yaml = yaml.safe_load(tosca_data)
        tosca_yaml["imports"][0]["template_file"] = \
            "https://raw.githubusercontent.com/grycap/tosca/main/templates/simple-node-disk.yml"
        tosca = Tosca(yaml.safe_dump(tosca_yaml))
        _, radl = tosca.to_radl()
        radl = parse_radl(str(radl))
        node = radl.get_system_by_name('simple_node')
        self.assertEqual(node.getValue("cpu.count"), 16)
        outputs = tosca.get_outputs(None)
        self.assertEqual(outputs.get('new_output'), 1)

        with self.assertRaises(Exception) as ex:
            tosca = Tosca(yaml.safe_dump(tosca_yaml),
                          tosca_repo="https://raw.githubusercontent.com/grycap/tosca/eosc_dc/templates/")
        expected_error = "Error parsing TOSCA template: The TOSCA template must be imported from the TOSCA " \
                         "repository: https://raw.githubusercontent.com/grycap/tosca/eosc_dc/templates/"
        self.assertEqual(expected_error, str(ex.exception))


if __name__ == "__main__":
    unittest.main()
