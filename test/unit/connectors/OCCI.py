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

import sys
import unittest
import json

sys.path.append(".")
sys.path.append("..")
from .CloudConn import TestCloudConnectorBase
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.OCCI import OCCICloudConnector
from IM.connectors.OCCI import KeyStoneAuth
from radl.radl import RADL, system, contextualize_item, configure
from mock import patch, MagicMock


class TestOCCIConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        self.return_error = False
        TestCloudConnectorBase.setUp(self)

    @staticmethod
    def get_occi_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "OCCI"
        cloud_info.protocol = "https"
        cloud_info.server = "server.com"
        cloud_info.port = 11443
        inf = MagicMock()
        inf.id = "1"
        cloud = OCCICloudConnector(cloud_info, inf)
        return cloud

    def test_concrete(self):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'https://server.com:11443/image' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        concrete = occi_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.AppDB.AppDB.get_site_id')
    @patch('IM.AppDB.AppDB.get_site_url')
    def test_concrete_appdb(self, get_site_url, get_site_id):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'appdb://CESNET-MetaCloud/egi.ubuntu.16.04?fedcloud.egi.eu' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy',
                                'host': 'https://carach5.ics.muni.cz:11443'}])
        occi_cloud = self.get_occi_cloud()
        occi_cloud.cloud.server = "carach5.ics.muni.cz"

        get_site_url.return_value = "https://carach5.ics.muni.cz:11443"
        get_site_id.return_value = "siteid"
        concrete = occi_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def get_response(self, method, url, verify, cert=None, headers=None, data=None):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]
        params = parts[4]

        if method not in self.call_count:
            self.call_count[method] = {}
        if url not in self.call_count[method]:
            self.call_count[method][url] = 0
        self.call_count[method][url] += 1

        resp.status_code = 404

        if method == "GET":
            if url == "":
                resp.status_code = 300
                resp.json.return_value = {"versions": {"values": [{"id": "v3.6"}, {"id": "v2.0"}]}}
            if url == "/-/":
                resp.status_code = 200
                resp.text = self.read_file_as_string("files/occi.txt")
            elif url == "/compute/1":
                resp.status_code = 200
                resp.text = self.read_file_as_string("files/occi_vm_info.txt")
            elif url.startswith("/storage"):
                resp.status_code = 200
                resp.text = 'X-OCCI-Attribute: occi.storage.state="online"'
            elif url == "/v2.0/tenants":
                resp.status_code = 200
                resp.json.return_value = {"tenants": [{"name": "tenantname"}]}
            elif url == "/v3/auth/projects":
                resp.status_code = 200
                resp.json.return_value = {"projects": [{"id": "projectid", "name": "prname"}]}
            elif url == "/v3/OS-FEDERATION/identity_providers/egi.eu/protocols/oidc/auth":
                resp.status_code = 200
                resp.headers = {'X-Subject-Token': 'token1'}
            elif url.endswith("/link/storagelink/compute_10_disk_1"):
                resp.status_code = 404
            elif url == "/rest/1.0/sites":
                resp.status_code = 200
                resp.text = """<appdb:appdb>
                                <appdb:site id="14454G0" name="CESNET-MetaCloud" infrastructure="Production"
                                status="Certified">
                                    <site:service type="openstack" id="4454G0" host="https://carach5.ics.muni.cz:5000">
                                    </site:service>
                                    <site:service type="occi" id="4455G0" host="https://carach5.ics.muni.cz:11443">
                                    </site:service>
                                </appdb:site>
                                </appdb:appdb>"""
            elif url == "/rest/1.0/va_providers/4454G0":
                resp.status_code = 200
                resp.text = """<appdb:appdb>
                                <virtualization:provider id="4454G0" in_production="true">
                                <provider:endpoint_url>https://carach5.ics.muni.cz:11443</provider:endpoint_url>
                                <provider:image
                                    vmiversion="2019.01.21"
                                    va_provider_image_id="http://url/os_tpl#image_id"
                                    appcname="egi.docker.ubuntu.16.04"
                                    voname="fedcloud.egi.eu"/>
                                <provider:image
                                    vmiversion="2019.01.21"
                                    va_provider_image_id="http://url/os_tpl#image_id2"
                                    appcname="egi.ubuntu.16.04"
                                    voname="fedcloud.egi.eu"/>
                                <provider:image
                                    vmiversion="2018.01.21"
                                    va_provider_image_id="http://url/os_tpl#image_id3"
                                    appcname="egi.ubuntu.16.04"
                                    voname="fedcloud.egi.eu"/>
                                </virtualization:provider>
                                </appdb:appdb>"""
            elif url == "/network/":
                resp.status_code = 200
                resp.text = ("X-OCCI-Location: http://server.com/network/1"
                             "\nX-OCCI-Location: http://server.com/network/2")
            elif url == "/network/2":
                resp.status_code = 200
                resp.text = "X-OCCI-Attribute: occi.network.address=\"158.42.0.0/24\""
            elif url == "/network/1":
                resp.status_code = 200
                resp.text = "X-OCCI-Attribute: occi.network.address=\"10.0.0.0/24\""
        elif method == "POST":
            if url == "/compute/":
                if self.return_error:
                    resp.status_code = 400
                    resp.reason = 'Error msg'
                    resp.text = ''
                else:
                    resp.status_code = 201
                    resp.text = 'https://server.com/compute/1'
            elif params == "action=suspend":
                resp.status_code = 204
            elif params == "action=start":
                resp.status_code = 200
            elif params == "action=restart":
                resp.status_code = 200
            elif url == "/storagelink/":
                resp.status_code = 200
            elif url == "/storage/":
                resp.status_code = 201
                resp.text = 'https://server.com/storage/1'
            elif url == "/networkinterface/":
                resp.status_code = 201
            elif url == "/v2.0/tokens":
                if json.loads(data) == {"auth": {"voms": True}}:
                    resp.status_code = 200
                    resp.json.return_value = {"access": {"token": {"id": "token1"}}}
                elif json.loads(data) == {"auth": {"voms": True, "tenantName": "tenantname"}}:
                    resp.status_code = 200
                    resp.json.return_value = {"access": {"token": {"id": "token2"}}}
                else:
                    resp.status_code = 400
            elif url == "/v3/auth/tokens":
                if json.loads(data) == {"auth": {"scope": {"project": {"id": "projectid"}},
                                                 "identity": {"token": {"id": "token1"}, "methods": ["token"]}}}:
                    resp.status_code = 200
                    resp.headers = {'X-Subject-Token': 'token3'}
                else:
                    resp.status_code = 400
        elif method == "DELETE":
            if url.endswith("/compute/1"):
                resp.status_code = 200
            elif url.endswith("/storage/1"):
                resp.status_code = 200
            elif url.endswith("/link/storagelink/compute_10_disk_1"):
                resp.status_code = 200
            elif url.endswith("/link/networkinterface/compute_10_nic_1"):
                resp.status_code = 200

        return resp

    @patch('requests.request')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, get_keystone_uri, requests):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'http://server.com/666956cb-9d15-475e-9f19-a3732c82a327' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path' and
            disk.2.image.url = 'http://server.com/storage/2'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'},
                               {'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'}])
        occi_cloud = self.get_occi_cloud()

        requests.side_effect = self.get_response
        get_keystone_uri.return_value = None, None

        inf = InfrastructureInfo()
        inf.auth = auth
        res = occi_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.return_error = True
        inf = InfrastructureInfo()
        inf.auth = auth
        res = occi_cloud.launch(inf, radl, radl, 1, auth)
        self.return_error = False
        success, msg = res[0]
        self.assertFalse(success)
        self.assertEqual(msg, "Error msg\n")
        self.assertEqual(self.call_count['DELETE']['/storage/1'], 1)
        self.assertNotIn('/storage/2', self.call_count['DELETE'])

    @patch('requests.request')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    def test_30_updateVMInfo(self, get_keystone_uri, requests):
        radl_data = """
            network net (outbound = 'yes')
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'https://server.com/666956cb-9d15-475e-9f19-a3732c82a327' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, radl, radl, occi_cloud, 1)

        requests.side_effect = self.get_response

        get_keystone_uri.return_value = None, None

        success, vm = occi_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        memory = vm.info.systems[0].getValue("memory.size")
        self.assertEqual(memory, 1824522240)

    @patch('requests.request')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    def test_40_stop(self, get_keystone_uri, requests):
        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, "", "", occi_cloud, 1)

        requests.side_effect = self.get_response

        get_keystone_uri.return_value = None, None

        success, _ = occi_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    def test_50_start(self, get_keystone_uri, requests):
        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, "", "", occi_cloud, 1)

        requests.side_effect = self.get_response

        get_keystone_uri.return_value = None, None

        success, _ = occi_cloud.start(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    def test_52_reboot(self, get_keystone_uri, requests):
        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, "", "", occi_cloud, 1)

        requests.side_effect = self.get_response

        get_keystone_uri.return_value = None, None

        success, _ = occi_cloud.reboot(vm, auth)

        self.assertTrue(success, msg="ERROR: rebooting VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('requests.request')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    def test_55_alter(self, get_keystone_uri, requests):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        new_radl_data = """
            network net ()
            network net1 (outbound = 'yes')
            system test (
            net_interface.0.connection = 'net' and
            net_interface.1.connection = 'net1' and
            disk.1.size=1GB and
            disk.1.device='hdc' and
            disk.1.fstype='ext4' and
            disk.1.mount_path='/mnt/disk'
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, radl, radl, occi_cloud, 1)

        requests.side_effect = self.get_response

        get_keystone_uri.return_value = None, None

        success, _ = occi_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        # Now test to delete the public IP
        radl_data = """
            network net ()
            network net1 (outbound = 'yes')
            system test (
            net_interface.0.connection = 'net' and
            net_interface.1.connection = 'net1' and
            net_interface.1.ip = '8.8.8.8' and
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            disk.0.os.name = 'linux'
            )"""
        radl = radl_parse.parse_radl(radl_data)

        new_radl_data = """
            network net ()
            system test (
            net_interface.0.connection = 'net' and
            disk.1.size=1GB and
            disk.1.device='hdc' and
            disk.1.fstype='ext4' and
            disk.1.mount_path='/mnt/disk'
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)

        vm = VirtualMachine(inf, "1", occi_cloud.cloud, radl, radl, occi_cloud, 1)
        success, _ = occi_cloud.alterVM(vm, new_radl, auth)
        self.assertTrue(success, msg="ERROR: modifying VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

        self.assertEqual(vm.requested_radl.systems[0].getValue("net_interface.0.connection"), "net")

    @patch('requests.request')
    @patch('IM.connectors.OCCI.KeyStoneAuth.get_keystone_uri')
    def test_60_finalize(self, get_keystone_uri, requests):
        auth = Authentication([{'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}])
        occi_cloud = self.get_occi_cloud()

        inf = MagicMock()
        radl = RADL()
        radl.systems.append(system("test"))
        vm = VirtualMachine(inf, "1", occi_cloud.cloud, radl, radl, occi_cloud, 1)

        requests.side_effect = self.get_response

        get_keystone_uri.return_value = None, None

        success, _ = occi_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def test_get_cloud_init_data(self):
        cloud_init = """
groups:
  - ubuntu: [foo,bar]
  - cloud-users
# Add users to the system. Users are added after groups are added.
users:
  - default
  - name: cloudy
    gecos: Magic Cloud App Daemon User
    inactive: true
    system: true
  - snapuser: joe@joeuser.io
packages:
 - pwgen
 - pastebinit
 - [libpython2.7, 2.7.3-0ubuntu3.1]
 """

        expected_res = """#cloud-config
merge_how: list(append)+dict(recurse_array,no_replace)+str()
users:
- lock-passwd: true
  name: user
  ssh-authorized-keys:
  - pub_key
  ssh-import-id: user
  sudo: ALL=(ALL) NOPASSWD:ALL
"""
        occi_cloud = self.get_occi_cloud()
        res = occi_cloud.get_cloud_init_data(None, None, "pub_key", "user")
        self.assertEqual(res, expected_res)

        radl_data = """
system node ()
configure node (
@begin
#!/bin/sh
touch /tmp/hello
@end
)
deploy node 1
contextualize (
    system node configure node with cloud_init
)"""
        radl = radl_parse.parse_radl(radl_data)
        occi_cloud = self.get_occi_cloud()
        res = occi_cloud.get_cloud_init_data(radl)
        self.assertEqual(res, "#!/bin/sh\ntouch /tmp/hello")

        expected_res = """#cloud-config
groups:
- ubuntu:
  - foo
  - bar
- cloud-users
merge_how: list(append)+dict(recurse_array,no_replace)+str()
packages:
- pwgen
- pastebinit
- - libpython2.7
  - 2.7.3-0ubuntu3.1
users:
- default
- gecos: Magic Cloud App Daemon User
  inactive: true
  name: cloudy
  system: true
- snapuser: joe@joeuser.io
- lock-passwd: true
  name: user
  ssh-authorized-keys:
  - pub_key
  ssh-import-id: user
  sudo: ALL=(ALL) NOPASSWD:ALL
"""
        radl = RADL()
        radl.systems.append(system("test"))
        citem = contextualize_item("test", "cid", ctxt_tool="cloud_init")
        radl.contextualize.items = {"id": citem}
        radl.configures.append(configure("cid", cloud_init))
        res = occi_cloud.get_cloud_init_data(radl, None, "pub_key", "user")
        self.assertEqual(res, expected_res)

    @patch('requests.request')
    def test_keystone_auth(self, requests):
        occi_cloud = self.get_occi_cloud()

        requests.side_effect = self.get_response

        auth = {'id': 'occi', 'type': 'OCCI', 'proxy': 'proxy', 'host': 'https://server.com:11443'}
        version = KeyStoneAuth.get_keystone_version(occi_cloud, "https://keystone.com:5000", auth)
        self.assertEqual(version, 2)

        token = KeyStoneAuth.get_keystone_token(occi_cloud, "https://keystone.com:5000", auth)
        self.assertEqual(token, "token2")

        auth = {'id': 'occi', 'type': 'OCCI', 'token': 'token', 'host': 'https://server.com:11443'}
        version = KeyStoneAuth.get_keystone_version(occi_cloud, "https://keystone.com:5000", auth)
        self.assertEqual(version, 3)

        token = KeyStoneAuth.get_keystone_token(occi_cloud, "https://keystone.com:5000", auth)
        self.assertEqual(token, "token3")


if __name__ == '__main__':
    unittest.main()
