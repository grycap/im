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
import json
import unittest
import sys
from mock import patch, MagicMock

sys.path.append("..")
sys.path.append(".")

from radl.radl_parse import parse_radl
from IM import __version__ as version
from IM.auth import Authentication
from IM.REST import (RESTDestroyInfrastructure,
                     RESTGetInfrastructureInfo,
                     RESTGetInfrastructureProperty,
                     RESTGetInfrastructureList,
                     RESTCreateInfrastructure,
                     RESTGetVMInfo,
                     RESTGetVMProperty,
                     RESTAddResource,
                     RESTRemoveResource,
                     RESTAlterVM,
                     RESTReconfigureInfrastructure,
                     RESTStartInfrastructure,
                     RESTStopInfrastructure,
                     RESTStartVM,
                     RESTStopVM,
                     RESTGeVersion)


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestREST(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

    @staticmethod
    def getAuth(im_users=[], vmrc_users=[], clouds=[]):
        return Authentication([
            {'id': 'im%s' % i, 'type': 'InfrastructureManager', 'username': 'user%s' % i,
             'password': 'pass%s' % i} for i in im_users] + [
            {'id': 'vmrc%s' % i, 'type': 'VMRC', 'username': 'vmrcuser%s' % i,
             'password': 'pass%s' % i, 'host': 'hostname'} for i in vmrc_users] + [
            {'id': 'cloud%s' % i, 'type': c, 'username': 'user%s' % i,
             'password': 'pass%s' % i, 'host': 'http://server.com:80/path'} for c, i in clouds])

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureList")
    @patch("bottle.request")
    def test_GetInfrastructureList(self, bottle_request, GetInfrastructureList):
        """Test REST GetInfrastructureList."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Accept": "application/json"}

        GetInfrastructureList.return_value = ["1", "2"]
        res = RESTGetInfrastructureList()
        self.assertEqual(res, ('{"uri-list": [{"uri": "http://imserver.com/infrastructures/1"},'
                               ' {"uri": "http://imserver.com/infrastructures/2"}]}'))

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureInfo")
    @patch("bottle.request")
    def test_GetInfrastructureInfo(self, bottle_request, GetInfrastructureInfo):
        """Test REST GetInfrastructureInfo."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        GetInfrastructureInfo.return_value = ["1", "2"]
        res = RESTGetInfrastructureInfo("1")
        self.assertEqual(res, ("http://imserver.com/infrastructures/1/vms/1\n"
                               "http://imserver.com/infrastructures/1/vms/2"))

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureContMsg")
    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureRADL")
    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureState")
    @patch("bottle.request")
    def test_GetInfrastructureProperty(self, bottle_request, GetInfrastructureState,
                                       GetInfrastructureRADL, GetInfrastructureContMsg):
        """Test REST GetInfrastructureProperty."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        GetInfrastructureState.return_value = {'state': "running", 'vm_states': {"vm1": "running", "vm2": "running"}}
        GetInfrastructureRADL.return_value = "radl"
        GetInfrastructureContMsg.return_value = "contmsg"

        res = RESTGetInfrastructureProperty("1", "state")
        self.assertEqual(json.loads(res)["state"]["state"], "running")

        res = RESTGetInfrastructureProperty("1", "contmsg")
        self.assertEqual(res, "contmsg")

        res = RESTGetInfrastructureProperty("1", "radl")
        self.assertEqual(res, "radl")

    @patch("IM.InfrastructureManager.InfrastructureManager.DestroyInfrastructure")
    @patch("bottle.request")
    def test_DestroyInfrastructure(self, bottle_request, DestroyInfrastructure):
        """Test REST DestroyInfrastructure."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        res = RESTDestroyInfrastructure("1")
        self.assertEqual(res, "")

    @patch("IM.InfrastructureManager.InfrastructureManager.CreateInfrastructure")
    @patch("bottle.request")
    def test_CreateInfrastructure(self, bottle_request, CreateInfrastructure):
        """Test REST CreateInfrastructure."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.body.read.return_value = "radl"

        CreateInfrastructure.return_value = "1"

        res = RESTCreateInfrastructure()
        self.assertEqual(res, "http://imserver.com/infrastructures/1")
        
        res = RESTCreateInfrastructure()
        self.assertEqual(res, "http://imserver.com/infrastructures/1")
        
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "application/json"}
        bottle_request.body.read.return_value = read_file_as_string("../files/test_simple.json")

        CreateInfrastructure.return_value = "1"

    @patch("IM.InfrastructureManager.InfrastructureManager.GetVMInfo")
    @patch("bottle.request")
    def test_GetVMInfo(self, bottle_request, GetVMInfo):
        """Test REST GetVMInfo."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Accept": "application/json"}

        GetVMInfo.return_value = parse_radl("system test (cpu.count = 1)")

        res = RESTGetVMInfo("1", "1")
        self.assertEqual(json.loads(res), json.loads('{"radl": [{"cpu.count": 1, "class": "system", "id": "test"}]}'))

        bottle_request.headers["Accept"] = "text/*"
        res = RESTGetVMInfo("1", "1")
        self.assertEqual(res, 'system test (\ncpu.count = 1\n)\n\n')

    @patch("IM.InfrastructureManager.InfrastructureManager.GetVMProperty")
    @patch("IM.InfrastructureManager.InfrastructureManager.GetVMContMsg")
    @patch("bottle.request")
    def test_GetVMProperty(self, bottle_request, GetVMContMsg, GetVMProperty):
        """Test REST GetVMProperty."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        GetVMProperty.return_value = "prop"
        GetVMContMsg.return_value = "contmsg"

        res = RESTGetVMProperty("1", "1", "prop")
        self.assertEqual(res, "prop")

        res = RESTGetVMProperty("1", "1", "contmsg")
        self.assertEqual(res, "contmsg")

    @patch("IM.InfrastructureManager.InfrastructureManager.AddResource")
    @patch("bottle.request")
    def test_AddResource(self, bottle_request, AddResource):
        """Test REST AddResource."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.body.read.return_value = "radl"
        bottle_request.params = {'context': 'yes'}

        AddResource.return_value = "1"

        res = RESTAddResource("1")
        self.assertEqual(res, "http://imserver.com/infrastructures/1/vms/1")
        
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "application/json"}
        bottle_request.body.read.return_value = read_file_as_string("../files/test_simple.json")
        
        res = RESTAddResource("1")
        self.assertEqual(res, "http://imserver.com/infrastructures/1/vms/1")

    @patch("IM.InfrastructureManager.InfrastructureManager.RemoveResource")
    @patch("bottle.request")
    def test_RemoveResource(self, bottle_request, RemoveResource):
        """Test REST RemoveResource."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.params = {'context': 'yes'}

        RemoveResource.return_value = 2

        res = RESTRemoveResource("1", "1,2")
        self.assertEqual(res, "")

    @patch("IM.InfrastructureManager.InfrastructureManager.AlterVM")
    @patch("bottle.request")
    def test_AlterVM(self, bottle_request, AlterVM):
        """Test REST AlterVM."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.body.read.return_value = "radl"
        bottle_request.params = {'context': 'yes'}

        AlterVM.return_value = "vm_info"

        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "vm_info")
        
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "application/json"}
        bottle_request.body.read.return_value = read_file_as_string("../files/test_simple.json")
        
        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "vm_info")

    @patch("IM.InfrastructureManager.InfrastructureManager.Reconfigure")
    @patch("bottle.request")
    def test_Reconfigure(self, bottle_request, Reconfigure):
        """Test REST Reconfigure."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.body.read.return_value = "radl"
        bottle_request.params = {'vm_list': '1,2'}

        Reconfigure.return_value = ""

        res = RESTReconfigureInfrastructure("1")
        self.assertEqual(res, "")
        
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "application/json"}
        bottle_request.body.read.return_value = read_file_as_string("../files/test_simple.json")
        
        res = RESTReconfigureInfrastructure("1")
        self.assertEqual(res, "")

    @patch("IM.InfrastructureManager.InfrastructureManager.StartInfrastructure")
    @patch("bottle.request")
    def test_StartInfrastructure(self, bottle_request, StartInfrastructure):
        """Test REST StartInfrastructure."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        StartInfrastructure.return_value = ""

        res = RESTStartInfrastructure("1")
        self.assertEqual(res, "")

    @patch("IM.InfrastructureManager.InfrastructureManager.StopInfrastructure")
    @patch("bottle.request")
    def test_StopInfrastructure(self, bottle_request, StopInfrastructure):
        """Test REST StopInfrastructure."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        StopInfrastructure.return_value = ""

        res = RESTStopInfrastructure("1")
        self.assertEqual(res, "")

    @patch("IM.InfrastructureManager.InfrastructureManager.StartVM")
    @patch("bottle.request")
    def test_StartVM(self, bottle_request, StartVM):
        """Test REST StartVM."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        StartVM.return_value = ""

        res = RESTStartVM("1", "1")
        self.assertEqual(res, "")

    @patch("IM.InfrastructureManager.InfrastructureManager.StopVM")
    @patch("bottle.request")
    def test_StopVM(self, bottle_request, StopVM):
        """Test REST StopVM."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        StopVM.return_value = ""

        res = RESTStopVM("1", "1")
        self.assertEqual(res, "")

    @patch("IM.InfrastructureManager.InfrastructureManager.StopVM")
    @patch("bottle.request")
    def test_GeVersion(self, bottle_request, StopVM):
        res = RESTGeVersion()
        self.assertEqual(res, version)


if __name__ == "__main__":
    unittest.main()
