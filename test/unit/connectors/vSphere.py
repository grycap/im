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

sys.path.append(".")
sys.path.append("..")
from .CloudConn import TestCloudConnectorBase
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.VirtualMachine import VirtualMachine
from IM.InfrastructureInfo import InfrastructureInfo
from IM.connectors.vSphere import vSphereCloudConnector
from mock import patch, MagicMock
from pyVmomi import vim


class TestvSphereConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    def setUp(self):
        self.vm_state = "poweredOn"
        TestCloudConnectorBase.setUp(self)

    @staticmethod
    def get_vsphere_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "vSphere"
        cloud_info.server = "vspherehost"
        inf = MagicMock()
        inf.id = "1"
        cloud = vSphereCloudConnector(cloud_info, inf)
        return cloud

    def test_10_concrete(self):
        radl_data = """
            network net ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net' and
            net_interface.0.dns_name = 'test' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'vsp://vspherehost/image-id' and
            disk.0.os.credentials.username = 'user'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'vsp', 'type': 'vSphere', 'host': 'https://vspherehost',
                                'username': 'user', 'password': 'password'}])
        vsphere_cloud = self.get_vsphere_cloud()

        concrete = vsphere_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    def CreateContainerView(self, rootFolder, type_list, flag):
        container = MagicMock()
        c = MagicMock()
        container.view = [c]
        if type_list[0] == vim.Datastore:
            c.name = "datastore"
        elif type_list[0] == vim.Network:
            c.name = "vsnet1"
            c.summary.ipPoolName = "ippool1"
            c2 = MagicMock()
            c2.name = "vsnet2"
            c2.summary.ipPoolName = "ippool2"
            container.view.append(c2)
        elif type_list[0] == vim.VirtualMachine:
            c.name = "vm-template"
            c.Clone.return_value = vim.Task("CreateVM")
            c.Suspend.return_value = vim.Task("SuspendVM")
            c.PowerOn.return_value = vim.Task("PowerOnVM")
            c.Reset.return_value = vim.Task("ResetVM")
            c.PowerOff.return_value = vim.Task("PowerOffVM")
            c.Destroy.return_value = vim.Task("DestroyVM")
            c.summary.runtime.powerState = self.vm_state
            c.runtime.powerState = self.vm_state
            nic1 = MagicMock()
            nic1.ipAddress = "10.0.0.1"
            nic2 = MagicMock()
            nic2.ipAddress = "8.8.8.8"
            c.guest.net = [nic1, nic2]
            dev1 = MagicMock()
            dev2 = vim.vm.device.VirtualSCSIController()
            c.config.hardware.device = [dev1, dev2]
            dev1.backing.fileName = ""
            dev1.unitNumber = 1
        else:
            raise Exception("Invalid type")

        return container

    @patch('IM.connectors.vSphere.vim')
    @patch('IM.connectors.vSphere.SmartConnect')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, conn, pvim):
        radl_data = """
            network net1 (outbound = 'yes' and outports = '8080,9000:9100')
            network net2 ()
            system test (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'net1' and
            net_interface.0.dns_name = 'test' and
            net_interface.1.connection = 'net2' and
            net_interface.1.ip = '10.0.0.2' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'vsp://vspherehost/vm-template' and
            disk.0.os.credentials.username = 'user' and
            disk.1.size=1GB and
            disk.1.device='hdb' and
            disk.1.mount_path='/mnt/path'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'vsp', 'type': 'vSphere', 'host': 'https://vspherehost',
                                'username': 'user', 'password': 'password'}])
        vsphere_cloud = self.get_vsphere_cloud()

        smatconn = MagicMock()
        conn.return_value = smatconn
        retcont = MagicMock()
        smatconn.RetrieveContent.return_value = retcont
        datacenter = MagicMock()
        retcont.rootFolder.childEntity = [datacenter]
        host = MagicMock()
        datacenter.hostFolder.childEntity = [host]
        retcont.viewManager.CreateContainerView.side_effect = self.CreateContainerView

        pvim.Datastore = vim.Datastore
        pvim.Network = vim.Network
        pvim.VirtualMachine = vim.VirtualMachine
        pvim.Task = vim.Task
        pvim.TaskInfo.State.success = vim.TaskInfo.State.success
        poolmgr = MagicMock()
        pvim.IpPoolManager.return_value = poolmgr
        ippool1 = MagicMock()
        ippool2 = MagicMock()
        poolmgr.QueryIpPools.return_value = [ippool1, ippool2]
        ippool1.name = "ippool1"
        ippool1.ipv4Config.subnetAddress = "10.0.0.1"
        ippool1.ipv4Config.netmask = "255.0.0.0"
        ippool2.name = "ippool2"
        ippool2.ipv4Config.subnetAddress = "8.8.8.8"
        ippool2.ipv4Config.netmask = "255.255.255.0"

        property_collector = MagicMock()
        smatconn.content.propertyCollector = property_collector
        update = MagicMock()
        property_collector.WaitForUpdates.return_value = update
        fs = MagicMock()
        update.filterSet = [fs]
        objs = MagicMock()
        fs.objectSet = [objs]
        change = MagicMock()
        objs.changeSet = [change]
        objs.obj = vim.Task("CreateVM")
        change.name = "info.state"
        change.val = vim.TaskInfo.State.success

        res = vsphere_cloud.launch_with_retry(InfrastructureInfo(), radl, radl, 3, auth, 2, 0)
        self.assertEqual(len(res), 3)
        self.assertTrue(res[0][0])
        self.assertTrue(res[1][0])
        self.assertTrue(res[2][0])

    @patch('IM.connectors.vSphere.vim')
    @patch('IM.connectors.vSphere.SmartConnect')
    def test_30_updateVMInfo(self, conn, pvim):
        radl_data = """
            network net (outbound = 'yes')
            network priv ()
            system test (
            cpu.arch='x86_64' and
            cpu.count=1 and
            memory.size=512m and
            net_interface.0.connection = 'net' and
            net_interface.1.connection = 'priv' and
            disk.0.os.name = 'linux' and
            disk.0.image.url = 'vsp://vspherehost/vm-template' and
            disk.0.os.credentials.username = 'user' and
            disk.0.os.credentials.password = 'pass' and
            disk.1.size=1GB
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'vsp', 'type': 'vSphere', 'host': 'https://vspherehost',
                                'username': 'user', 'password': 'password'}])
        vsphere_cloud = self.get_vsphere_cloud()

        smatconn = MagicMock()
        conn.return_value = smatconn
        retcont = MagicMock()
        smatconn.RetrieveContent.return_value = retcont
        retcont.viewManager.CreateContainerView.side_effect = self.CreateContainerView
        pvim.VirtualMachine = vim.VirtualMachine
        pvim.vm.device.VirtualSCSIController = vim.vm.device.VirtualSCSIController

        inf = MagicMock()
        vm = VirtualMachine(inf, "vm-template", vsphere_cloud.cloud, radl, radl, vsphere_cloud, 1)

        success, vm = vsphere_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEqual(vm.info.systems[0].getValue('net_interface.1.ip'), "10.0.0.1")
        self.assertEqual(vm.info.systems[0].getValue('net_interface.0.ip'), "8.8.8.8")

    @patch('IM.connectors.vSphere.vim')
    @patch('IM.connectors.vSphere.SmartConnect')
    def test_40_stop(self, conn, pvim):
        auth = Authentication([{'id': 'vsp', 'type': 'vSphere', 'host': 'https://vspherehost',
                                'username': 'user', 'password': 'password'}])
        vsphere_cloud = self.get_vsphere_cloud()

        smatconn = MagicMock()
        conn.return_value = smatconn
        retcont = MagicMock()
        smatconn.RetrieveContent.return_value = retcont
        retcont.viewManager.CreateContainerView.side_effect = self.CreateContainerView
        pvim.VirtualMachine = vim.VirtualMachine

        pvim.TaskInfo.State.success = vim.TaskInfo.State.success
        pvim.Task = vim.Task
        property_collector = MagicMock()
        smatconn.content.propertyCollector = property_collector
        update = MagicMock()
        property_collector.WaitForUpdates.return_value = update
        fs = MagicMock()
        update.filterSet = [fs]
        objs = MagicMock()
        fs.objectSet = [objs]
        change = MagicMock()
        objs.changeSet = [change]
        objs.obj = vim.Task("SuspendVM")
        change.name = "info.state"
        change.val = vim.TaskInfo.State.success

        inf = MagicMock()
        vm = VirtualMachine(inf, "vm-template", vsphere_cloud.cloud, "", "", vsphere_cloud, 1)

        success, _ = vsphere_cloud.stop(vm, auth)

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.vSphere.vim')
    @patch('IM.connectors.vSphere.SmartConnect')
    def test_50_start(self, conn, pvim):
        auth = Authentication([{'id': 'vsp', 'type': 'vSphere', 'host': 'https://vspherehost',
                                'username': 'user', 'password': 'password'}])
        vsphere_cloud = self.get_vsphere_cloud()

        smatconn = MagicMock()
        conn.return_value = smatconn
        retcont = MagicMock()
        smatconn.RetrieveContent.return_value = retcont
        retcont.viewManager.CreateContainerView.side_effect = self.CreateContainerView
        pvim.VirtualMachine = vim.VirtualMachine

        pvim.TaskInfo.State.success = vim.TaskInfo.State.success
        pvim.Task = vim.Task
        property_collector = MagicMock()
        smatconn.content.propertyCollector = property_collector
        update = MagicMock()
        property_collector.WaitForUpdates.return_value = update
        fs = MagicMock()
        update.filterSet = [fs]
        objs = MagicMock()
        fs.objectSet = [objs]
        change = MagicMock()
        objs.changeSet = [change]
        objs.obj = vim.Task("PowerOnVM")
        change.name = "info.state"
        change.val = vim.TaskInfo.State.success
        inf = MagicMock()
        vm = VirtualMachine(inf, "vm-template", vsphere_cloud.cloud, "", "", vsphere_cloud, 1)

        self.vm_state = "suspended"
        success, _ = vsphere_cloud.start(vm, auth)
        self.vm_state = "poweredOn"

        self.assertTrue(success, msg="ERROR: stopping VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.vSphere.vim')
    @patch('IM.connectors.vSphere.SmartConnect')
    def test_52_reboot(self, conn, pvim):
        auth = Authentication([{'id': 'vsp', 'type': 'vSphere', 'host': 'https://vspherehost',
                                'username': 'user', 'password': 'password'}])
        vsphere_cloud = self.get_vsphere_cloud()

        smatconn = MagicMock()
        conn.return_value = smatconn
        retcont = MagicMock()
        smatconn.RetrieveContent.return_value = retcont
        retcont.viewManager.CreateContainerView.side_effect = self.CreateContainerView
        pvim.VirtualMachine = vim.VirtualMachine

        pvim.TaskInfo.State.success = vim.TaskInfo.State.success
        pvim.Task = vim.Task
        property_collector = MagicMock()
        smatconn.content.propertyCollector = property_collector
        update = MagicMock()
        property_collector.WaitForUpdates.return_value = update
        fs = MagicMock()
        update.filterSet = [fs]
        objs = MagicMock()
        fs.objectSet = [objs]
        change = MagicMock()
        objs.changeSet = [change]
        objs.obj = vim.Task("ResetVM")
        change.name = "info.state"
        change.val = vim.TaskInfo.State.success
        inf = MagicMock()
        vm = VirtualMachine(inf, "vm-template", vsphere_cloud.cloud, "", "", vsphere_cloud, 1)

        success, _ = vsphere_cloud.reboot(vm, auth)

        self.assertTrue(success, msg="ERROR: rebooting VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('IM.connectors.vSphere.vim')
    @patch('IM.connectors.vSphere.SmartConnect')
    def test_60_finalize(self, conn, pvim):
        auth = Authentication([{'id': 'vsp', 'type': 'vSphere', 'host': 'https://vspherehost',
                                'username': 'user', 'password': 'password'}])
        vsphere_cloud = self.get_vsphere_cloud()

        smatconn = MagicMock()
        conn.return_value = smatconn
        retcont = MagicMock()
        smatconn.RetrieveContent.return_value = retcont
        retcont.viewManager.CreateContainerView.side_effect = self.CreateContainerView
        pvim.VirtualMachine = vim.VirtualMachine

        pvim.TaskInfo.State.success = vim.TaskInfo.State.success
        pvim.Task = vim.Task
        property_collector = MagicMock()
        smatconn.content.propertyCollector = property_collector
        update = MagicMock()
        property_collector.WaitForUpdates.return_value = update
        fs = MagicMock()
        update.filterSet = [fs]
        obj1 = MagicMock()
        obj2 = MagicMock()
        fs.objectSet = [obj1, obj2]
        change = MagicMock()
        obj1.changeSet = [change]
        obj1.obj = vim.Task("PowerOffVM")
        obj2.changeSet = [change]
        obj2.obj = vim.Task("DestroyVM")
        change.name = "info.state"
        change.val = vim.TaskInfo.State.success
        inf = MagicMock()
        vm = VirtualMachine(inf, "vm-template", vsphere_cloud.cloud, "", "", vsphere_cloud, 1)

        success, _ = vsphere_cloud.finalize(vm, True, auth)

        self.assertTrue(success, msg="ERROR: finalizing VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
