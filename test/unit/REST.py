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
from io import BytesIO
from mock import patch, MagicMock
from IM.InfrastructureInfo import InfrastructureInfo
from IM.auth import Authentication
from IM.VirtualMachine import VirtualMachine
from radl.radl_parse import parse_radl

sys.path.append("..")
sys.path.append(".")

from IM import __version__ as version
from IM.InfrastructureManager import (DeletedInfrastructureException,
                                      IncorrectInfrastructureException,
                                      UnauthorizedUserException,
                                      InvaliddUserException)
from IM.InfrastructureInfo import IncorrectVMException, DeletedVMException, IncorrectStateException
from IM.REST import app
from IM.config import Config
import defusedxml.ElementTree as etree


def read_file_as_bytes(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    with open(abs_file_path, 'r') as f:
        return BytesIO(f.read().encode())


class TestREST(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

    def setUp(self):
        self.client = app.test_client()

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureList")
    def test_GetInfrastructureList(self, GetInfrastructureList):
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass"),
                   "Accept": "application/json"}

        GetInfrastructureList.return_value = ["1", "2"]
        res = self.client.get('/infrastructures', headers=headers)
        self.assertEqual(200, res.status_code)
        self.assertEqual(res.json, ({"uri-list": [{"uri": "http://localhost/infrastructures/1"},
                                                  {"uri": "http://localhost/infrastructures/2"}]}))

        GetInfrastructureList.side_effect = InvaliddUserException()
        res = self.client.get('/infrastructures', headers=headers)
        self.assertEqual(401, res.status_code)
        self.assertEqual(res.json, {"message": "Error Getting Inf. List: Invalid InfrastructureManager credentials",
                                    "code": 401})

        GetInfrastructureList.side_effect = UnauthorizedUserException()
        res = self.client.get('/infrastructures', headers=headers)
        self.assertEqual(400, res.status_code)
        self.assertEqual(res.json, {"message": "Error Getting Inf. List: Access to this infrastructure not granted.",
                                    "code": 400})

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureInfo")
    def test_GetInfrastructureInfo(self, GetInfrastructureInfo):
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        GetInfrastructureInfo.return_value = ["1", "2"]
        res = self.client.get('/infrastructures/1', headers=headers)
        self.assertEqual(200, res.status_code)
        self.assertEqual(res.text, ("http://localhost/infrastructures/1/vms/1\n"
                                    "http://localhost/infrastructures/1/vms/2"))

        GetInfrastructureInfo.side_effect = DeletedInfrastructureException()
        res = self.client.get('/infrastructures/1', headers=headers)
        self.assertEqual(404, res.status_code)
        self.assertEqual(res.text, "Error Getting Inf. info: Deleted infrastructure.")

        GetInfrastructureInfo.side_effect = IncorrectInfrastructureException()
        res = self.client.get('/infrastructures/1', headers=headers)
        self.assertEqual(404, res.status_code)
        self.assertEqual(res.text, "Error Getting Inf. info: Invalid infrastructure ID or access not granted.")

        GetInfrastructureInfo.side_effect = UnauthorizedUserException()
        res = self.client.get('/infrastructures/1', headers=headers)
        self.assertEqual(403, res.status_code)
        self.assertEqual(res.text, "Error Getting Inf. info: Access to this infrastructure not granted.")

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureContMsg")
    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureRADL")
    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureState")
    @patch("IM.InfrastructureManager.InfrastructureManager.get_infrastructure")
    def test_GetInfrastructureProperty(self, get_infrastructure, GetInfrastructureState,
                                       GetInfrastructureRADL, GetInfrastructureContMsg):
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        GetInfrastructureState.return_value = {'state': "running", 'vm_states': {"vm1": "running", "vm2": "running"}}
        GetInfrastructureRADL.return_value = "radl"
        GetInfrastructureContMsg.return_value = "contmsg"

        inf = MagicMock()
        get_infrastructure.return_value = inf
        tosca = MagicMock()
        inf.extra_info = {"TOSCA": tosca}
        tosca.get_outputs.return_value = "outputs"
        tosca.serialize.return_value = "tosca"

        res = self.client.get('/infrastructures/1/state', headers=headers)
        self.assertEqual(res.json["state"]["state"], "running")

        res = self.client.get('/infrastructures/1/contmsg', headers=headers)
        self.assertEqual(res.text, "contmsg")

        res = self.client.get('/infrastructures/1/contmsg?headeronly=yes', headers=headers)
        self.assertEqual(res.text, "contmsg")

        res = self.client.get('/infrastructures/1/contmsg?headeronly=no', headers=headers)
        self.assertEqual(res.text, "contmsg")

        res = self.client.get('/infrastructures/1/radl', headers=headers)
        self.assertEqual(res.text, "radl")

        res = self.client.get('/infrastructures/1/outputs', headers=headers)
        self.assertEqual(res.json, {"outputs": "outputs"})

        res = self.client.get('/infrastructures/1/tosca', headers=headers)
        self.assertEqual(res.text, "tosca")

        GetInfrastructureRADL.side_effect = DeletedInfrastructureException()
        res = self.client.get('/infrastructures/1/radl', headers=headers)
        self.assertEqual(res.text, "Error Getting Inf. prop: Deleted infrastructure.")

        GetInfrastructureRADL.side_effect = IncorrectInfrastructureException()
        res = self.client.get('/infrastructures/1/radl', headers=headers)
        self.assertEqual(res.text, "Error Getting Inf. prop: Invalid infrastructure ID or access not granted.")

        GetInfrastructureRADL.side_effect = UnauthorizedUserException()
        res = self.client.get('/infrastructures/1/radl', headers=headers)
        self.assertEqual(res.text, "Error Getting Inf. prop: Access to this infrastructure not granted.")

    @patch("IM.InfrastructureManager.InfrastructureManager.DestroyInfrastructure")
    def test_DestroyInfrastructure(self, DestroyInfrastructure):
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        res = self.client.delete('/infrastructures/1', headers=headers)
        self.assertEqual(res.text, "")
        self.assertEqual(DestroyInfrastructure.call_args_list[0][0][0], "1")
        self.assertEqual(DestroyInfrastructure.call_args_list[0][0][2], False)

        res = self.client.delete('/infrastructures/1?force=yes', headers=headers)
        self.assertEqual(res.text, "")
        self.assertEqual(DestroyInfrastructure.call_args_list[1][0][0], "1")
        self.assertEqual(DestroyInfrastructure.call_args_list[1][0][2], True)

        res = self.client.delete('/infrastructures/1?async=yes', headers=headers)
        self.assertEqual(res.text, "")
        self.assertEqual(DestroyInfrastructure.call_args_list[2][0][0], "1")
        self.assertEqual(DestroyInfrastructure.call_args_list[2][0][3], True)

        DestroyInfrastructure.side_effect = DeletedInfrastructureException()
        res = self.client.delete('/infrastructures/1', headers=headers)
        self.assertEqual(res.text, "Error Destroying Inf: Deleted infrastructure.")

        DestroyInfrastructure.side_effect = IncorrectInfrastructureException()
        res = self.client.delete('/infrastructures/1', headers=headers)
        self.assertEqual(res.text, "Error Destroying Inf: Invalid infrastructure ID or access not granted.")

        DestroyInfrastructure.side_effect = UnauthorizedUserException()
        res = self.client.delete('/infrastructures/1', headers=headers)
        self.assertEqual(res.text, "Error Destroying Inf: Access to this infrastructure not granted.")

        DestroyInfrastructure.side_effect = IncorrectStateException()
        res = self.client.delete('/infrastructures/1', headers=headers)
        self.assertEqual(res.text, "Error Destroying Inf: Invalid State to perform this operation.")

    @patch("IM.InfrastructureManager.InfrastructureManager.CreateInfrastructure")
    @patch("IM.InfrastructureManager.InfrastructureManager.get_infrastructure")
    def test_CreateInfrastructure(self, get_infrastructure, CreateInfrastructure):
        """Test REST CreateInfrastructure."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = ramses.i3m.upv.es:2633; "
                                     "username = user; password = pass")}
        CreateInfrastructure.return_value = "1"

        res = self.client.post('/infrastructures', headers=headers, data=BytesIO(b"radl"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1")
        self.assertEqual(res.headers['InfID'], "1")

        res = self.client.post('/infrastructures?async=yes', headers=headers, data=BytesIO(b"radl"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1")

        headers["Content-Type"] = "application/json"
        res = self.client.post('/infrastructures', headers=headers,
                               data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1")

        headers["Content-Type"] = "text/yaml"
        res = self.client.post('/infrastructures', headers=headers,
                               data=read_file_as_bytes("../files/tosca_simple.yml"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1")

        headers["Content-Type"] = "application/json"
        # Test the dry_run option to get the estimation of the resources
        res = self.client.post('/infrastructures?dry_run=yes', headers=headers,
                               data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.json, {"one": {"cloudType": "OpenNebula",
                                            "cloudEndpoint": "http://ramses.i3m.upv.es:2633",
                                            "compute": [{"cpuCores": 1, "memoryInMegabytes": 1074, "publicIP": 1},
                                                        {"cpuCores": 1, "memoryInMegabytes": 1074}], "storage": []}})

        headers["Content-Type"] = "application/json"
        CreateInfrastructure.side_effect = InvaliddUserException()
        res = self.client.post('/infrastructures', headers=headers,
                               data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error Creating Inf. info: Invalid InfrastructureManager credentials")

        CreateInfrastructure.side_effect = UnauthorizedUserException()
        res = self.client.post('/infrastructures', headers=headers,
                               data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error Creating Inf.: Access to this infrastructure not granted.")

    @patch("IM.InfrastructureManager.InfrastructureManager.CreateInfrastructure")
    def test_CreateInfrastructureWithErrors(self, CreateInfrastructure):
        """Test REST CreateInfrastructure."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass"),
                   "Content-Type": "application/pdf", "Accept": "application/json"}

        CreateInfrastructure.return_value = "1"

        res = self.client.post('/infrastructures', headers=headers, data=BytesIO(b"radl"))
        self.assertEqual(res.json['code'], 415)

    @patch("IM.InfrastructureManager.InfrastructureManager.GetVMInfo")
    def test_GetVMInfo(self, GetVMInfo):
        """Test REST GetVMInfo."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass"),
                   "Accept": "application/json"}

        GetVMInfo.return_value = parse_radl("system test (cpu.count = 1)")

        res = self.client.get('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.json, {"radl": [{"cpu.count": 1, "class": "system", "id": "test"}]})

        headers["Accept"] = "text/*"
        res = self.client.get('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, 'system test (\ncpu.count = 1\n)\n\n')

        GetVMInfo.side_effect = DeletedInfrastructureException()
        res = self.client.get('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. info: Deleted infrastructure.")

        GetVMInfo.side_effect = IncorrectInfrastructureException()
        res = self.client.get('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. info: Invalid infrastructure ID or access not granted.")

        GetVMInfo.side_effect = UnauthorizedUserException()
        res = self.client.get('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. info: Access to this infrastructure not granted.")

        GetVMInfo.side_effect = DeletedVMException()
        res = self.client.get('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. info: Deleted VM.")

        GetVMInfo.side_effect = IncorrectVMException()
        res = self.client.get('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. info: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.GetVMProperty")
    @patch("IM.InfrastructureManager.InfrastructureManager.GetVMContMsg")
    def test_GetVMProperty(self, GetVMContMsg, GetVMProperty):
        """Test REST GetVMProperty."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        GetVMProperty.return_value = "prop"
        GetVMContMsg.return_value = "contmsg"

        res = self.client.get('/infrastructures/1/vms/1/prop', headers=headers)
        self.assertEqual(res.text, "prop")

        res = self.client.get('/infrastructures/1/vms/1/contmsg', headers=headers)
        self.assertEqual(res.text, "contmsg")

        GetVMProperty.side_effect = DeletedInfrastructureException()
        res = self.client.get('/infrastructures/1/vms/1/prop', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. property: Deleted infrastructure.")

        GetVMProperty.side_effect = IncorrectInfrastructureException()
        res = self.client.get('/infrastructures/1/vms/1/prop', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. property: Invalid infrastructure ID or access not granted.")

        GetVMProperty.side_effect = UnauthorizedUserException()
        res = self.client.get('/infrastructures/1/vms/1/prop', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. property: Access to this infrastructure not granted.")

        GetVMProperty.side_effect = DeletedVMException()
        res = self.client.get('/infrastructures/1/vms/1/prop', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. property: Deleted VM.")

        GetVMProperty.side_effect = IncorrectVMException()
        res = self.client.get('/infrastructures/1/vms/1/prop', headers=headers)
        self.assertEqual(res.text, "Error Getting VM. property: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.AddResource")
    @patch("IM.InfrastructureManager.InfrastructureManager.get_infrastructure")
    def test_AddResource(self, get_infrastructure, AddResource):
        """Test REST AddResource."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        AddResource.return_value = "1"

        res = self.client.post('/infrastructures/1?context=yes', headers=headers, data=BytesIO(b"radl"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1/vms/1")
        self.assertEqual(res.headers['InfID'], "1")

        headers["Content-Type"] = "application/json"
        res = self.client.post('/infrastructures/1', headers=headers,
                               data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1/vms/1")

        headers["Content-Type"] = "text/yaml"
        res = self.client.post('/infrastructures/1', headers=headers,
                               data=read_file_as_bytes("../files/tosca_simple.yml"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1/vms/1")

        headers["Content-Type"] = "application/json"
        AddResource.side_effect = DeletedInfrastructureException()
        res = self.client.post('/infrastructures/1', headers=headers,
                               data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error Adding resources: Deleted infrastructure.")

        AddResource.side_effect = IncorrectInfrastructureException()
        res = self.client.post('/infrastructures/1', headers=headers,
                               data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error Adding resources: Invalid infrastructure ID or access not granted.")

        AddResource.side_effect = UnauthorizedUserException()
        res = self.client.post('/infrastructures/1', headers=headers,
                               data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error Adding resources: Access to this infrastructure not granted.")

    @patch("IM.InfrastructureManager.InfrastructureManager.RemoveResource")
    def test_RemoveResource(self, RemoveResource):
        """Test REST RemoveResource."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        RemoveResource.return_value = 2

        res = self.client.delete('/infrastructures/1/vms/1,2?context=yes', headers=headers)
        self.assertEqual(res.text, "")

        RemoveResource.side_effect = DeletedInfrastructureException()
        res = self.client.delete('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Removing resources: Deleted infrastructure.")

        RemoveResource.side_effect = IncorrectInfrastructureException()
        res = self.client.delete('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Removing resources: Invalid infrastructure ID or access not granted.")

        RemoveResource.side_effect = UnauthorizedUserException()
        res = self.client.delete('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Removing resources: Access to this infrastructure not granted.")

        RemoveResource.side_effect = DeletedVMException()
        res = self.client.delete('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Removing resources: Deleted VM.")

        RemoveResource.side_effect = IncorrectVMException()
        res = self.client.delete('/infrastructures/1/vms/1', headers=headers)
        self.assertEqual(res.text, "Error Removing resources: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.AlterVM")
    def test_AlterVM(self, AlterVM):
        """Test REST AlterVM."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        AlterVM.return_value = "vm_info"

        res = self.client.put('/infrastructures/1/vms/1?context=yes', headers=headers, data=BytesIO(b"radl"))
        self.assertEqual(res.text, "vm_info")

        headers["Content-Type"] = "text/yaml"
        res = self.client.put('/infrastructures/1/vms/1', headers=headers,
                              data=read_file_as_bytes("../files/tosca_simple.yml"))
        self.assertEqual(res.text, "vm_info")

        headers["Content-Type"] = "application/json"
        res = self.client.put('/infrastructures/1/vms/1', headers=headers,
                              data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "vm_info")

        AlterVM.side_effect = DeletedInfrastructureException()
        res = self.client.put('/infrastructures/1/vms/1', headers=headers,
                              data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error modifying resources: Deleted infrastructure.")

        AlterVM.side_effect = IncorrectInfrastructureException()
        res = self.client.put('/infrastructures/1/vms/1', headers=headers,
                              data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error modifying resources: Invalid infrastructure ID or access not granted.")

        AlterVM.side_effect = UnauthorizedUserException()
        res = self.client.put('/infrastructures/1/vms/1', headers=headers,
                              data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error modifying resources: Access to this infrastructure not granted.")

        AlterVM.side_effect = DeletedVMException()
        res = self.client.put('/infrastructures/1/vms/1', headers=headers,
                              data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error modifying resources: Deleted VM.")

        AlterVM.side_effect = IncorrectVMException()
        res = self.client.put('/infrastructures/1/vms/1', headers=headers,
                              data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error modifying resources: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.Reconfigure")
    def test_Reconfigure(self, Reconfigure):
        """Test REST Reconfigure."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        Reconfigure.return_value = ""

        res = self.client.put('/infrastructures/1/reconfigure?vmlist=1,2', headers=headers, data=BytesIO(b"radl"))
        self.assertEqual(res.text, "")
        self.assertEqual(res.headers['InfID'], "1")

        headers["Content-Type"] = "application/json"
        res = self.client.put('/infrastructures/1/reconfigure?vmlist=1,2',
                              headers=headers, data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "")

        Reconfigure.side_effect = DeletedInfrastructureException()
        res = self.client.put('/infrastructures/1/reconfigure?vmlist=1,2',
                              headers=headers, data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error in reconfigure operation: Deleted infrastructure.")

        Reconfigure.side_effect = IncorrectInfrastructureException()
        res = self.client.put('/infrastructures/1/reconfigure?vmlist=1,2',
                              headers=headers, data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, ("Error in reconfigure operation: " +
                                    "Invalid infrastructure ID or access not granted."))

        Reconfigure.side_effect = UnauthorizedUserException()
        res = self.client.put('/infrastructures/1/reconfigure?vmlist=1,2',
                              headers=headers, data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error in reconfigure operation: Access to this infrastructure not granted.")

    @patch("IM.InfrastructureManager.InfrastructureManager.StartInfrastructure")
    @patch("IM.InfrastructureManager.InfrastructureManager.StopInfrastructure")
    def test_OperateInfrastructure(self, StopInfrastructure, StartInfrastructure):
        """Test REST StartInfrastructure and StopInfrastructure."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        for op in ["start", "stop"]:
            StartInfrastructure.side_effect = None
            StopInfrastructure.side_effect = None
            StartInfrastructure.return_value = ""
            StopInfrastructure.return_value = ""

            res = self.client.put('/infrastructures/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "")

            StartInfrastructure.side_effect = DeletedInfrastructureException()
            StopInfrastructure.side_effect = DeletedInfrastructureException()
            res = self.client.put('/infrastructures/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "Error in %s operation: Deleted infrastructure." % op)

            StartInfrastructure.side_effect = IncorrectInfrastructureException()
            StopInfrastructure.side_effect = IncorrectInfrastructureException()
            res = self.client.put('/infrastructures/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "Error in %s operation: Invalid infrastructure ID or access not granted." % op)

            StartInfrastructure.side_effect = UnauthorizedUserException()
            StopInfrastructure.side_effect = UnauthorizedUserException()
            res = self.client.put('/infrastructures/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "Error in %s operation: Access to this infrastructure not granted." % op)

    @patch("IM.InfrastructureManager.InfrastructureManager.StartVM")
    @patch("IM.InfrastructureManager.InfrastructureManager.StopVM")
    @patch("IM.InfrastructureManager.InfrastructureManager.RebootVM")
    def test_OperateVM(self, RebootVM, StopVM, StartVM):
        """Test REST StartVM, StopVM and Reboot."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        for op in ["start", "stop", "reboot"]:
            StartVM.side_effect = None
            StartVM.return_value = ""
            StopVM.side_effect = None
            StopVM.return_value = ""
            RebootVM.side_effect = None
            RebootVM.return_value = ""

            res = self.client.put('/infrastructures/1/vms/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "")

            StartVM.side_effect = DeletedInfrastructureException()
            StopVM.side_effect = DeletedInfrastructureException()
            RebootVM.side_effect = DeletedInfrastructureException()
            res = self.client.put('/infrastructures/1/vms/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "Error in %s op in VM: Deleted infrastructure." % op)

            StartVM.side_effect = IncorrectInfrastructureException()
            StopVM.side_effect = IncorrectInfrastructureException()
            RebootVM.side_effect = IncorrectInfrastructureException()
            res = self.client.put('/infrastructures/1/vms/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "Error in %s op in VM: Invalid infrastructure ID or access not granted." % op)

            StartVM.side_effect = UnauthorizedUserException()
            StopVM.side_effect = UnauthorizedUserException()
            RebootVM.side_effect = UnauthorizedUserException()
            res = self.client.put('/infrastructures/1/vms/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "Error in %s op in VM: Access to this infrastructure not granted." % op)

            StartVM.side_effect = DeletedVMException()
            StopVM.side_effect = DeletedVMException()
            RebootVM.side_effect = DeletedVMException()
            res = self.client.put('/infrastructures/1/vms/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "Error in %s op in VM: Deleted VM." % op)

            StartVM.side_effect = IncorrectVMException()
            StopVM.side_effect = IncorrectVMException()
            RebootVM.side_effect = IncorrectVMException()
            res = self.client.put('/infrastructures/1/vms/1/%s' % op, headers=headers)
            self.assertEqual(res.text, "Error in %s op in VM: Invalid VM ID" % op)

    def test_GeVersion(self):
        res = self.client.get('/version')
        self.assertEqual(res.text, version)

    def test_Index(self):
        res = self.client.get('/')
        self.assertIn("IM REST API", res.text)

    @patch("IM.InfrastructureManager.InfrastructureManager.CreateDiskSnapshot")
    def test_CreateDiskSnapshot(self, CreateDiskSnapshot):
        """Test REST StopVM."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        CreateDiskSnapshot.return_value = "one://server.com/image_url"

        res = self.client.put('/infrastructures/1/vms/1/disks/0/snapshot?image_name=image_url&auto_delete=yes',
                              headers=headers)
        self.assertEqual(res.text, "one://server.com/image_url")

        CreateDiskSnapshot.side_effect = DeletedInfrastructureException()
        res = self.client.put('/infrastructures/1/vms/1/disks/0/snapshot?image_name=image_url&auto_delete=yes',
                              headers=headers)
        self.assertEqual(res.text, "Error creating snapshot: Deleted infrastructure.")

        CreateDiskSnapshot.side_effect = IncorrectInfrastructureException()
        res = self.client.put('/infrastructures/1/vms/1/disks/0/snapshot?image_name=image_url&auto_delete=yes',
                              headers=headers)
        self.assertEqual(res.text, "Error creating snapshot: Invalid infrastructure ID or access not granted.")

        CreateDiskSnapshot.side_effect = UnauthorizedUserException()
        res = self.client.put('/infrastructures/1/vms/1/disks/0/snapshot?image_name=image_url&auto_delete=yes',
                              headers=headers)
        self.assertEqual(res.text, "Error creating snapshot: Access to this infrastructure not granted.")

        CreateDiskSnapshot.side_effect = DeletedVMException()
        res = self.client.put('/infrastructures/1/vms/1/disks/0/snapshot?image_name=image_url&auto_delete=yes',
                              headers=headers)
        self.assertEqual(res.text, "Error creating snapshot: Deleted VM.")

        CreateDiskSnapshot.side_effect = IncorrectVMException()
        res = self.client.put('/infrastructures/1/vms/1/disks/0/snapshot?image_name=image_url&auto_delete=yes',
                              headers=headers)
        self.assertEqual(res.text, "Error creating snapshot: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.ExportInfrastructure")
    def test_ExportInfrastructure(self, ExportInfrastructure):
        """Test REST StopInfrastructure."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        ExportInfrastructure.return_value = "strinf"

        res = self.client.get('/infrastructures/1/data', headers=headers)
        self.assertEqual(res.json, {"data": "strinf"})

    @patch("IM.InfrastructureManager.InfrastructureManager.ImportInfrastructure")
    def test_ImportInfrastructure(self, ImportInfrastructure):
        """Test REST StopInfrastructure."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        ImportInfrastructure.return_value = "newid"

        res = self.client.put('/infrastructures', headers=headers, data=BytesIO(b'{"data": "strinf"}'))
        self.assertEqual(res.text, "http://localhost/infrastructures/newid")

    @patch("IM.VirtualMachine.SSH")
    @patch("IM.InfrastructureManager.InfrastructureManager.get_infrastructure")
    @patch("IM.InfrastructureManager.InfrastructureManager.check_auth_data")
    def test_commands(self, check_auth_data, get_infrastructure, SSH):
        """Test REST StopInfrastructure."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        inf = InfrastructureInfo()
        inf.id = "1"
        inf.auth = Authentication([{'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'}])
        get_infrastructure.return_value = inf

        res = self.client.get('/infrastructures/1/vms/1/command?step=1', headers=headers)
        auth_str = "Authorization: type = InfrastructureManager; username = user; password = pass"
        url = "http://localhost/infrastructures/1/vms/1/command?step=2"
        ps_command = "ps aux | grep -v grep | grep 'ssh -N -R'"
        expected_res = """
                    res="wait"
                    while [ "$res" == "wait" ]
                    do
                    res=`curl --insecure -s -H "%s" -H "Accept: text/plain" %s`
                    if [ "$res" != "wait" ]
                    then
                        echo "$res" > /var/tmp/reverse_ssh.sh
                        chmod a+x /var/tmp/reverse_ssh.sh
                        /var/tmp/reverse_ssh.sh
                        if [ "$res" != "true" ]
                        then
                        echo "*/1 * * * * root %s || /var/tmp/reverse_ssh.sh" > /etc/cron.d/reverse_ssh
                        fi
                    else
                        sleep 20
                    fi
                    done""" % (auth_str, url, ps_command)
        self.assertEqual(res.text, expected_res)

        inf.auth = Authentication([{'type': 'InfrastructureManager', 'token': 'token'}])
        res = self.client.get('/infrastructures/1/vms/1/command?step=1', headers=headers)
        auth_str = "Authorization: type = InfrastructureManager; token = token"
        url = "http://localhost/infrastructures/1/vms/1/command?step=2"
        expected_res = """
                    res="wait"
                    while [ "$res" == "wait" ]
                    do
                    res=`curl --insecure -s -H "%s" -H "Accept: text/plain" %s`
                    if [ "$res" != "wait" ]
                    then
                        echo "$res" > /var/tmp/reverse_ssh.sh
                        chmod a+x /var/tmp/reverse_ssh.sh
                        /var/tmp/reverse_ssh.sh
                        if [ "$res" != "true" ]
                        then
                        echo "*/1 * * * * root %s || /var/tmp/reverse_ssh.sh" > /etc/cron.d/reverse_ssh
                        fi
                    else
                        sleep 20
                    fi
                    done""" % (auth_str, url, ps_command)
        self.assertEqual(res.text, expected_res)

        radl_master = parse_radl("""
            network publica (outbound = 'yes')
            network privada ()

            system front (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.ip = '8.8.8.8' and
            net_interface.0.connection = 'publica' and
            net_interface.1.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux'
            )
        """)

        radl_vm1 = parse_radl("""
            network privada ()

            system wn (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'privada' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux'
            )
        """)

        radl_vm2 = parse_radl("""
            network privada2 ()

            system wn2 (
            cpu.arch='x86_64' and
            cpu.count>=1 and
            memory.size>=512m and
            net_interface.0.connection = 'privada2' and
            disk.0.image.url = 'mock0://linux.for.ev.er' and
            disk.0.os.credentials.username = 'ubuntu' and
            disk.0.os.credentials.password = 'yoyoyo' and
            disk.0.os.name = 'linux'
            )
        """)

        # in the Master VM
        inf.vm_master = VirtualMachine(inf, None, None, radl_master, radl_master)
        inf.vm_master.creation_im_id = 0
        ssh = MagicMock()
        ssh.test_connectivity.return_value = True
        ssh.port = 22
        ssh.private_key = None
        ssh.password = "yoyoyo"
        ssh.username = "ubuntu"
        ssh.host = "8.8.8.8"
        SSH.return_value = ssh
        vm1 = VirtualMachine(inf, None, None, radl_vm1, radl_vm1)
        vm1.creation_im_id = 1
        vm1.destroy = False
        vm2 = VirtualMachine(inf, None, None, radl_vm2, radl_vm2)
        vm2.creation_im_id = 2
        vm2.destroy = False
        inf.vm_list = [inf.vm_master, vm1, vm2]

        res = self.client.get('/infrastructures/1/vms/0/command?step=2', headers=headers)
        expected_res = "true"
        self.assertEqual(res.text, expected_res)

        res = self.client.get('/infrastructures/1/vms/1/command?step=2', headers=headers)
        expected_res = "true"
        self.assertEqual(res.text, expected_res)

        # in VM not connected to the Master VM
        res = self.client.get('/infrastructures/1/vms/2/command?step=2', headers=headers)
        expected_res = ('sshpass -pyoyoyo ssh -N -R 20002:localhost:22 -p 22 -o "UserKnownHostsFile=/dev/null"'
                        ' -o "StrictHostKeyChecking=no" ubuntu@8.8.8.8 &')
        self.assertEqual(res.text, expected_res)

    def test_GetCloudInfo(self):
        """Test REST GetCloudInfo."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = cloud1; type = Dummy; host = http://dummy;")}

        res = self.client.get('/clouds/cloud1/images', headers=headers)
        self.assertEqual(res.json, {"images": [{"uri": "mock0://linux.for.ev.er/image1",
                                                "name": "Image Name1"},
                                               {"uri": "mock0://linux.for.ev.er/image2",
                                                "name": "Image Name2"}]})

        res = self.client.get('/clouds/cloud1/quotas', headers=headers)
        self.assertEqual(res.json, {"quotas": {"cores": {"used": 1, "limit": 10},
                                               "ram": {"used": 1, "limit": 10},
                                               "instances": {"used": 1, "limit": 10},
                                               "floating_ips": {"used": 1, "limit": 10},
                                               "security_groups": {"used": 1, "limit": 10}}})

    @patch("IM.InfrastructureManager.InfrastructureManager.GetCloudImageList")
    def test_GetCloudInfo_filters(self, GetCloudImageList):
        """Test REST GetCloudInfo with filters."""
        headers = {"AUTHORIZATION": "type = InfrastructureManager; username = user; password = pass"}

        GetCloudImageList.return_value = []
        res = self.client.get('/clouds/cloud1/images?filters=region=region_name', headers=headers)
        self.assertEqual(res.json, {"images": []})
        self.assertEqual(GetCloudImageList.call_args_list[0][0][2], {'region': 'region_name'})

    @patch("IM.InfrastructureManager.InfrastructureManager.ChangeInfrastructureAuth")
    def test_ChangeInfrastructureAuth(self, ChangeInfrastructureAuth):
        """Test REST ChangeInfrastructureAuth."""
        headers = {"AUTHORIZATION": "type = InfrastructureManager; username = user; password = pass"}
        ChangeInfrastructureAuth.return_value = None

        res = self.client.post('/infrastructures/infid/authorization?overwrite=yes',
                               headers=headers, data=b'{"username": "new_user", "password": "new_pass"}')
        self.assertEqual(res.text, "")

        self.assertEqual(ChangeInfrastructureAuth.call_args_list[0][0][0], "infid")
        self.assertEqual(ChangeInfrastructureAuth.call_args_list[0][0][1].auth_list, [{"type": "InfrastructureManager",
                                                                                       "username": "new_user",
                                                                                       "password": "new_pass"}])
        self.assertEqual(ChangeInfrastructureAuth.call_args_list[0][0][2], True)

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureOwners")
    def test_GetInfrastructureOwners(self, GetInfrastructureOwners):
        """Test REST StopInfrastructure."""
        headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\\n"
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}

        GetInfrastructureOwners.return_value = ["user1", "user2"]

        res = self.client.get('/infrastructures/1/authorization', headers=headers)
        self.assertEqual(res.text, 'user1\nuser2')

        headers["Accept"] = "application/json"
        res = self.client.get('/infrastructures/1/authorization', headers=headers)
        self.assertEqual(res.json, {"authorization": ["user1", "user2"]})

    @patch("IM.InfrastructureManager.InfrastructureManager.GetStats")
    def test_GetStats(self, GetStats):
        """Test REST GetStats."""
        headers = {"AUTHORIZATION": "type = InfrastructureManager; username = user; password = pass"}
        GetStats.return_value = [{"key": 1}]

        res = self.client.get('/stats?init_date=2010-01-01&end_date=2022-01-01', headers=headers)

        self.assertEqual(res.json, {"stats": [{"key": 1}]})
        self.assertEqual(GetStats.call_args_list[0][0][0], '2010-01-01')
        self.assertEqual(GetStats.call_args_list[0][0][1], '2022-01-01')
        self.assertEqual(GetStats.call_args_list[0][0][2].auth_list, [{"type": "InfrastructureManager",
                                                                       "username": "user",
                                                                       "password": "pass"}])

    @patch("requests_cache.CachedSession")
    def test_oaipmh(self, CachedSession):
        """Test OAIPMH."""
        Config.OAIPMH_REPO_BASE_IDENTIFIER_URL = "https://github.com/grycap/tosca/blob/eosc_lot1/templates/"
        Config.OAIPMH_REPO_DESCRIPTION = "TOSCA templates"
        Config.OAIPMH_REPO_NAME = "TOSCA"
        Config.OAIPMH_REPO_ADMIN_EMAIL = "some@some.com"

        list_resp = MagicMock()
        list_resp.json.return_value = {
            "tree":
            [{'path': 'templates/docker.yaml', 'mode': '100644', 'type': 'blob',
              'sha': 'a97c8105a8e9020aa6061a88034a019f869a4096', 'size': 5141,
              'url': 'https://api.github.com/repos/grycap/tosca/git/blobs/a97c8105a8e9020aa6061a88034a019f869a4096'},
             {'path': 'templates/hadoop_cluster.yaml', 'mode': '100644', 'type': 'blob',
              'sha': '13d4233c0a34cbd4e320aa2336817fcf1ec8d773', 'size': 3748,
              'url': 'https://api.github.com/repos/grycap/tosca/git/blobs/13d4233c0a34cbd4e320aa2336817fcf1ec8d773'}]}
        file_resp1 = MagicMock()
        file_resp1.text = """metadata:
  template_name: VM
  template_version: "1.1.0"
  template_author: Miguel Caballer
  creation_date: 2020-09-08
  display_name: Deploy a VM"""
        file_resp2 = MagicMock()
        file_resp2.text = """metadata:
  template_name: VM2
  template_version: "1.1.0"
  template_author: Miguel Caballer
  creation_date: 2020-09-09
  display_name: Deploy a VM2"""
        session = MagicMock()
        CachedSession.return_value = session
        session.get.side_effect = [list_resp, file_resp1, file_resp2]

        namespace = {'oaipmh': 'http://www.openarchives.org/OAI/2.0/'}

        # Test OAI path
        res = self.client.get('/oai')
        self.assertEqual(200, res.status_code)
        root = etree.fromstring(res.data)
        self.assertEqual(root.find(".//oaipmh:error", namespace).attrib['code'], 'badVerb')

        # Test Identify
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=Identify')
        self.assertEqual(200, res.status_code)

        root = etree.fromstring(res.data)

        self.assertEqual(root.find(".//oaipmh:repositoryName", namespace).text, "TOSCA")
        self.assertEqual(root.find(".//oaipmh:baseURL", namespace).text, "http://localhost/oai")
        self.assertEqual(root.find(".//oaipmh:protocolVersion", namespace).text, "2.0")
        self.assertIsNotNone(root.find(".//oaipmh:earliestDatestamp", namespace))
        self.assertEqual(root.find(".//oaipmh:deletedRecord", namespace).text, "no")
        self.assertEqual(root.find(".//oaipmh:granularity", namespace).text, "YYYY-MM-DD")
        self.assertEqual(root.find(".//oaipmh:adminEmail", namespace).text, "some@some.com")

        # Test Identify Post with body params
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.post('/oai', headers={'Content-Type': 'application/x-www-form-urlencoded'},
                               data="verb=Identify")
        self.assertEqual(200, res.status_code)
        root = etree.fromstring(res.data)
        self.assertEqual(root.find(".//oaipmh:repositoryName", namespace).text, "TOSCA")

        namespaces = {'dc': 'http://purl.org/dc/elements/1.1/',
                      'oaipmh': 'http://www.openarchives.org/OAI/2.0/',
                      'datacite': 'http://datacite.org/schema/kernel-4'}

        # Test GetRecord
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        tosca_id = "https://github.com/grycap/tosca/blob/eosc_lot1/templates/hadoop_cluster.yaml"
        res = self.client.get('/oai?verb=GetRecord&metadataPrefix=oai_datacite&identifier=%s' % tosca_id)
        self.assertEqual(200, res.status_code)

        root = etree.fromstring(res.data)

        self.assertEqual(root.find(".//datacite:title", namespaces).text, "Deploy a VM2")
        self.assertEqual(root.find(".//datacite:creatorName", namespaces).text, "Miguel Caballer")
        self.assertEqual(root.find(".//datacite:date", namespaces).text, "2020-09-09")
        self.assertEqual(root.find(".//oaipmh:identifier", namespaces).text, tosca_id)
        self.assertEqual(root.find(".//oaipmh:datestamp", namespaces).text, "2020-09-09")
        self.assertEqual(root.find(".//datacite:identifier", namespaces).text, tosca_id)

        # Test GetRecord with invalid identifier
        tosca_id = 'invalid"id'
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=GetRecord&metadataPrefix=oai_dc&identifier=%s' % tosca_id)
        self.assertEqual(200, res.status_code)
        root = etree.fromstring(res.data)
        self.assertEqual(root.find(".//oaipmh:error", namespace).attrib['code'], 'idDoesNotExist')

        # Test ListIdentifiers
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=ListIdentifiers&metadataPrefix=oai_dc')
        self.assertEqual(200, res.status_code)
        root = etree.fromstring(res.data)
        elems = root.findall(".//oaipmh:header", namespaces)
        self.assertEqual(len(elems), 2)

        self.assertEqual(root.find(".//oaipmh:identifier", namespaces).text,
                         "https://github.com/grycap/tosca/blob/eosc_lot1/templates/docker.yaml")

        # Test ListIdentifiers with from
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=ListIdentifiers&metadataPrefix=oai_dc&from=2020-09-10')
        self.assertEqual(200, res.status_code)
        root = etree.fromstring(res.data)
        self.assertEqual(root.find(".//oaipmh:error", namespace).attrib['code'], 'noRecordsMatch')

        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=ListIdentifiers&metadataPrefix=oai_dc&from=2020-09-07')
        self.assertEqual(200, res.status_code)
        root = etree.fromstring(res.data)
        elems = root.findall(".//oaipmh:header", namespaces)
        self.assertEqual(len(elems), 2)

        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=ListIdentifiers&metadataPrefix=oai_dc&until=2020-09-07')
        self.assertEqual(200, res.status_code)
        root = etree.fromstring(res.data)
        self.assertEqual(root.find(".//oaipmh:error", namespace).attrib['code'], 'noRecordsMatch')

        # Test ListRecords oai_dc
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=ListRecords&metadataPrefix=oai_dc')
        self.assertEqual(200, res.status_code)

        root = etree.fromstring(res.data)

        self.assertEqual(root.find(".//dc:title", namespaces).text, "Deploy a VM")
        self.assertEqual(root.find(".//dc:creator", namespaces).text, "Miguel Caballer")
        self.assertEqual(root.find(".//dc:date", namespaces).text, "2020-09-08")
        self.assertEqual(root.find(".//oaipmh:identifier", namespaces).text,
                         "https://github.com/grycap/tosca/blob/eosc_lot1/templates/docker.yaml")
        self.assertEqual(root.find(".//oaipmh:datestamp", namespaces).text,
                         "2020-09-08")
        # self.assertIsNotNone(root.find(".//dc:type", namespace_dc))
        # self.assertIsNotNone(root.find(".//dc:rights", namespace_dc))

        # Test ListRecords oai_openaire
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=ListRecords&metadataPrefix=oai_openaire')
        self.assertEqual(200, res.status_code)
        root = etree.fromstring(res.data)
        elems = root.findall(".//oaipmh:identifier", namespaces)
        self.assertEqual(len(elems), 2)
        self.assertEqual(root.find(".//dc:creator", namespaces).text, "Miguel Caballer")

        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=ListRecords&metadataPrefix=oai_dc&until=2020-09-07')
        self.assertEqual(200, res.status_code)
        root = etree.fromstring(res.data)
        self.assertEqual(root.find(".//oaipmh:error", namespace).attrib['code'], 'noRecordsMatch')

        # Test ListMetadataFormats
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=ListMetadataFormats')
        self.assertEqual(200, res.status_code)

        root = etree.fromstring(res.data)

        prefixes = root.findall(".//oaipmh:metadataPrefix", namespaces)
        prefixes_text = [prefix.text for prefix in prefixes]

        self.assertIn('oai_dc', prefixes_text)
        self.assertIn('oai_openaire', prefixes_text)
        self.assertIn('oai_datacite', prefixes_text)

        # Test ListSets
        session.get.side_effect = [list_resp, file_resp1, file_resp2]
        res = self.client.get('/oai?verb=ListSets')
        self.assertEqual(200, res.status_code)

        root = etree.fromstring(res.data)

        self.assertEqual(root.find(".//oaipmh:error", namespace).attrib['code'], 'noSetHierarchy')


if __name__ == "__main__":
    unittest.main()
