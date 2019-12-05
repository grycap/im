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
from io import BytesIO
from mock import patch, MagicMock
from IM.InfrastructureInfo import InfrastructureInfo
from IM.auth import Authentication
from IM.VirtualMachine import VirtualMachine
from radl.radl_parse import parse_radl

sys.path.append("..")
sys.path.append(".")

from IM.config import Config
from IM import __version__ as version
from IM.InfrastructureManager import (DeletedInfrastructureException,
                                      IncorrectInfrastructureException,
                                      UnauthorizedUserException,
                                      InvaliddUserException)
from IM.InfrastructureInfo import IncorrectVMException, DeletedVMException, IncorrectStateException
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
                     RESTRebootVM,
                     RESTGeVersion,
                     RESTCreateDiskSnapshot,
                     RESTImportInfrastructure,
                     return_error,
                     format_output)


def read_file_as_bytes(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return BytesIO(open(abs_file_path, 'r').read().encode())


class TestREST(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

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

        GetInfrastructureList.side_effect = InvaliddUserException()
        res = RESTGetInfrastructureList()
        res = json.loads(res)
        self.assertEqual(res, {"message": "Error Getting Inf. List: Invalid InfrastructureManager credentials",
                               "code": 401})

        GetInfrastructureList.side_effect = UnauthorizedUserException()
        res = RESTGetInfrastructureList()
        res = json.loads(res)
        self.assertEqual(res, {"message": "Error Getting Inf. List: Access to this infrastructure not granted.",
                               "code": 400})

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureList")
    @patch("bottle.request")
    def test_GetInfrastructureListSingleSite(self, bottle_request, GetInfrastructureList):
        """Test REST GetInfrastructureList."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()

        Config.SINGLE_SITE = True
        Config.SINGLE_SITE_AUTH_HOST = 'host'

        Config.SINGLE_SITE_TYPE = 'OpenNebula'
        Config.SINGLE_SITE_IMAGE_URL_PREFIX = 'one'
        bottle_request.headers = {"AUTHORIZATION": "Basic dXNlcjpwYXNz", "Accept": "application/json"}
        GetInfrastructureList.return_value = ["1", "2"]
        res = RESTGetInfrastructureList()
        self.assertEqual(res, ('{"uri-list": [{"uri": "http://imserver.com/infrastructures/1"},'
                               ' {"uri": "http://imserver.com/infrastructures/2"}]}'))

        Config.SINGLE_SITE_TYPE = 'OpenStack'
        Config.SINGLE_SITE_IMAGE_URL_PREFIX = 'ost'
        bottle_request.headers = {"AUTHORIZATION": "Bearer access_token", "Accept": "application/json"}
        GetInfrastructureList.return_value = ["1", "2"]
        res = RESTGetInfrastructureList()
        self.assertEqual(res, ('{"uri-list": [{"uri": "http://imserver.com/infrastructures/1"},'
                               ' {"uri": "http://imserver.com/infrastructures/2"}]}'))
        Config.SINGLE_SITE = False

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureList")
    @patch("bottle.request")
    def test_GetInfrastructureListWithErrors(self, bottle_request, GetInfrastructureList):
        """Test REST GetInfrastructureList without auth data."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"Accept": "application/json"}

        GetInfrastructureList.return_value = ["1", "2"]
        res = RESTGetInfrastructureList()
        res_json = json.loads(res)
        self.assertEqual(res_json['code'], 401)

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

        GetInfrastructureInfo.side_effect = DeletedInfrastructureException()
        res = RESTGetInfrastructureInfo("1")
        self.assertEqual(res, "Error Getting Inf. info: Deleted infrastructure.")

        GetInfrastructureInfo.side_effect = IncorrectInfrastructureException()
        res = RESTGetInfrastructureInfo("1")
        self.assertEqual(res, "Error Getting Inf. info: Invalid infrastructure ID or access not granted.")

        GetInfrastructureInfo.side_effect = UnauthorizedUserException()
        res = RESTGetInfrastructureInfo("1")
        self.assertEqual(res, "Error Getting Inf. info: Access to this infrastructure not granted.")

    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureContMsg")
    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureRADL")
    @patch("IM.InfrastructureManager.InfrastructureManager.GetInfrastructureState")
    @patch("IM.InfrastructureManager.InfrastructureManager.get_infrastructure")
    @patch("bottle.request")
    def test_GetInfrastructureProperty(self, bottle_request, get_infrastructure, GetInfrastructureState,
                                       GetInfrastructureRADL, GetInfrastructureContMsg):
        """Test REST GetInfrastructureProperty."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
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

        res = RESTGetInfrastructureProperty("1", "state")
        self.assertEqual(json.loads(res)["state"]["state"], "running")

        res = RESTGetInfrastructureProperty("1", "contmsg")
        self.assertEqual(res, "contmsg")

        bottle_request.params = {'headeronly': 'yes'}
        res = RESTGetInfrastructureProperty("1", "contmsg")
        self.assertEqual(res, "contmsg")

        bottle_request.params = {'headeronly': 'no'}
        res = RESTGetInfrastructureProperty("1", "contmsg")
        self.assertEqual(res, "contmsg")

        res = RESTGetInfrastructureProperty("1", "radl")
        self.assertEqual(res, "radl")

        res = RESTGetInfrastructureProperty("1", "outputs")
        self.assertEqual(res, '{"outputs": "outputs"}')

        res = RESTGetInfrastructureProperty("1", "tosca")
        self.assertEqual(res, "tosca")

        GetInfrastructureRADL.side_effect = DeletedInfrastructureException()
        res = RESTGetInfrastructureProperty("1", "radl")
        self.assertEqual(res, "Error Getting Inf. prop: Deleted infrastructure.")

        GetInfrastructureRADL.side_effect = IncorrectInfrastructureException()
        res = RESTGetInfrastructureProperty("1", "radl")
        self.assertEqual(res, "Error Getting Inf. prop: Invalid infrastructure ID or access not granted.")

        GetInfrastructureRADL.side_effect = UnauthorizedUserException()
        res = RESTGetInfrastructureProperty("1", "radl")
        self.assertEqual(res, "Error Getting Inf. prop: Access to this infrastructure not granted.")

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
        self.assertEqual(DestroyInfrastructure.call_args_list[0][0][0], "1")
        self.assertEqual(DestroyInfrastructure.call_args_list[0][0][2], False)

        bottle_request.params = {"force": "yes"}
        res = RESTDestroyInfrastructure("1")
        self.assertEqual(res, "")
        self.assertEqual(DestroyInfrastructure.call_args_list[1][0][0], "1")
        self.assertEqual(DestroyInfrastructure.call_args_list[1][0][2], True)

        bottle_request.params = {"async": "yes"}
        res = RESTDestroyInfrastructure("1")
        self.assertEqual(res, "")
        self.assertEqual(DestroyInfrastructure.call_args_list[2][0][0], "1")
        self.assertEqual(DestroyInfrastructure.call_args_list[2][0][3], True)

        DestroyInfrastructure.side_effect = DeletedInfrastructureException()
        res = RESTDestroyInfrastructure("1")
        self.assertEqual(res, "Error Destroying Inf: Deleted infrastructure.")

        DestroyInfrastructure.side_effect = IncorrectInfrastructureException()
        res = RESTDestroyInfrastructure("1")
        self.assertEqual(res, "Error Destroying Inf: Invalid infrastructure ID or access not granted.")

        DestroyInfrastructure.side_effect = UnauthorizedUserException()
        res = RESTDestroyInfrastructure("1")
        self.assertEqual(res, "Error Destroying Inf: Access to this infrastructure not granted.")

        DestroyInfrastructure.side_effect = IncorrectStateException()
        res = RESTDestroyInfrastructure("1")
        self.assertEqual(res, "Error Destroying Inf: Invalid State to perform this operation.")

    @patch("IM.InfrastructureManager.InfrastructureManager.CreateInfrastructure")
    @patch("IM.InfrastructureManager.InfrastructureManager.get_infrastructure")
    @patch("bottle.request")
    def test_CreateInfrastructure(self, bottle_request, get_infrastructure, CreateInfrastructure):
        """Test REST CreateInfrastructure."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.body = BytesIO(b"radl")

        CreateInfrastructure.return_value = "1"

        res = RESTCreateInfrastructure()
        self.assertEqual(res, "http://imserver.com/infrastructures/1")

        bottle_request.params = {"async": "yes"}
        res = RESTCreateInfrastructure()
        self.assertEqual(res, "http://imserver.com/infrastructures/1")

        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "application/json"}
        bottle_request.body = read_file_as_bytes("../files/test_simple.json")

        CreateInfrastructure.return_value = "1"

        res = RESTCreateInfrastructure()
        self.assertEqual(res, "http://imserver.com/infrastructures/1")

        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "text/yaml"}
        bottle_request.body = read_file_as_bytes("../files/tosca_create.yml")

        CreateInfrastructure.return_value = "1"

        res = RESTCreateInfrastructure()
        self.assertEqual(res, "http://imserver.com/infrastructures/1")

        bottle_request.body = read_file_as_bytes("../files/tosca_create.yml")
        CreateInfrastructure.side_effect = InvaliddUserException()
        res = RESTCreateInfrastructure()
        self.assertEqual(res, "Error Getting Inf. info: Invalid InfrastructureManager credentials")

        bottle_request.body = read_file_as_bytes("../files/tosca_create.yml")
        CreateInfrastructure.side_effect = UnauthorizedUserException()
        res = RESTCreateInfrastructure()
        self.assertEqual(res, "Error Creating Inf.: Access to this infrastructure not granted.")

    @patch("IM.InfrastructureManager.InfrastructureManager.CreateInfrastructure")
    @patch("bottle.request")
    def test_CreateInfrastructureWithErrors(self, bottle_request, CreateInfrastructure):
        """Test REST CreateInfrastructure."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "application/pdf", "Accept": "application/json"}
        bottle_request.body = BytesIO(b"radl")

        CreateInfrastructure.return_value = "1"

        res = RESTCreateInfrastructure()
        res_json = json.loads(res)
        self.assertEqual(res_json['code'], 415)

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

        GetVMInfo.side_effect = DeletedInfrastructureException()
        res = RESTGetVMInfo("1", "1")
        self.assertEqual(res, "Error Getting VM. info: Deleted infrastructure.")

        GetVMInfo.side_effect = IncorrectInfrastructureException()
        res = RESTGetVMInfo("1", "1")
        self.assertEqual(res, "Error Getting VM. info: Invalid infrastructure ID or access not granted.")

        GetVMInfo.side_effect = UnauthorizedUserException()
        res = RESTGetVMInfo("1", "1")
        self.assertEqual(res, "Error Getting VM. info: Access to this infrastructure not granted.")

        GetVMInfo.side_effect = DeletedVMException()
        res = RESTGetVMInfo("1", "1")
        self.assertEqual(res, "Error Getting VM. info: Deleted VM.")

        GetVMInfo.side_effect = IncorrectVMException()
        res = RESTGetVMInfo("1", "1")
        self.assertEqual(res, "Error Getting VM. info: Invalid VM ID")

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

        GetVMProperty.side_effect = DeletedInfrastructureException()
        res = RESTGetVMProperty("1", "1", "prop")
        self.assertEqual(res, "Error Getting VM. property: Deleted infrastructure.")

        GetVMProperty.side_effect = IncorrectInfrastructureException()
        res = RESTGetVMProperty("1", "1", "prop")
        self.assertEqual(res, "Error Getting VM. property: Invalid infrastructure ID or access not granted.")

        GetVMProperty.side_effect = UnauthorizedUserException()
        res = RESTGetVMProperty("1", "1", "prop")
        self.assertEqual(res, "Error Getting VM. property: Access to this infrastructure not granted.")

        GetVMProperty.side_effect = DeletedVMException()
        res = RESTGetVMProperty("1", "1", "prop")
        self.assertEqual(res, "Error Getting VM. property: Deleted VM.")

        GetVMProperty.side_effect = IncorrectVMException()
        res = RESTGetVMProperty("1", "1", "prop")
        self.assertEqual(res, "Error Getting VM. property: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.AddResource")
    @patch("IM.InfrastructureManager.InfrastructureManager.get_infrastructure")
    @patch("bottle.request")
    def test_AddResource(self, bottle_request, get_infrastructure, AddResource):
        """Test REST AddResource."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.body = BytesIO(b"radl")
        bottle_request.params = {'context': 'yes'}

        AddResource.return_value = "1"

        res = RESTAddResource("1")
        self.assertEqual(res, "http://imserver.com/infrastructures/1/vms/1")

        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "application/json"}
        bottle_request.body = read_file_as_bytes("../files/test_simple.json")

        res = RESTAddResource("1")
        self.assertEqual(res, "http://imserver.com/infrastructures/1/vms/1")

        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "text/yaml"}
        bottle_request.body = read_file_as_bytes("../files/tosca_create.yml")

        res = RESTAddResource("1")
        self.assertEqual(res, "http://imserver.com/infrastructures/1/vms/1")

        bottle_request.body = read_file_as_bytes("../files/tosca_create.yml")
        AddResource.side_effect = DeletedInfrastructureException()
        res = RESTAddResource("1")
        self.assertEqual(res, "Error Adding resources: Deleted infrastructure.")

        bottle_request.body = read_file_as_bytes("../files/tosca_create.yml")
        AddResource.side_effect = IncorrectInfrastructureException()
        res = RESTAddResource("1")
        self.assertEqual(res, "Error Adding resources: Invalid infrastructure ID or access not granted.")

        bottle_request.body = read_file_as_bytes("../files/tosca_create.yml")
        AddResource.side_effect = UnauthorizedUserException()
        res = RESTAddResource("1")
        self.assertEqual(res, "Error Adding resources: Access to this infrastructure not granted.")

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

        RemoveResource.side_effect = DeletedInfrastructureException()
        res = RESTRemoveResource("1", "1,2")
        self.assertEqual(res, "Error Removing resources: Deleted infrastructure.")

        RemoveResource.side_effect = IncorrectInfrastructureException()
        res = RESTRemoveResource("1", "1,2")
        self.assertEqual(res, "Error Removing resources: Invalid infrastructure ID or access not granted.")

        RemoveResource.side_effect = UnauthorizedUserException()
        res = RESTRemoveResource("1", "1,2")
        self.assertEqual(res, "Error Removing resources: Access to this infrastructure not granted.")

        RemoveResource.side_effect = DeletedVMException()
        res = RESTRemoveResource("1", "1,2")
        self.assertEqual(res, "Error Removing resources: Deleted VM.")

        RemoveResource.side_effect = IncorrectVMException()
        res = RESTRemoveResource("1", "1,2")
        self.assertEqual(res, "Error Removing resources: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.AlterVM")
    @patch("bottle.request")
    def test_AlterVM(self, bottle_request, AlterVM):
        """Test REST AlterVM."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.body = BytesIO(b"radl")
        bottle_request.params = {'context': 'yes'}

        AlterVM.return_value = "vm_info"

        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "vm_info")

        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "text/yaml"}
        bottle_request.body = read_file_as_bytes("../files/tosca_create.yml")

        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "vm_info")

        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "application/json"}
        bottle_request.body = read_file_as_bytes("../files/test_simple.json")

        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "vm_info")

        bottle_request.body = read_file_as_bytes("../files/test_simple.json")
        AlterVM.side_effect = DeletedInfrastructureException()
        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "Error modifying resources: Deleted infrastructure.")

        bottle_request.body = read_file_as_bytes("../files/test_simple.json")
        AlterVM.side_effect = IncorrectInfrastructureException()
        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "Error modifying resources: Invalid infrastructure ID or access not granted.")

        bottle_request.body = read_file_as_bytes("../files/test_simple.json")
        AlterVM.side_effect = UnauthorizedUserException()
        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "Error modifying resources: Access to this infrastructure not granted.")

        bottle_request.body = read_file_as_bytes("../files/test_simple.json")
        AlterVM.side_effect = DeletedVMException()
        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "Error modifying resources: Deleted VM.")

        bottle_request.body = read_file_as_bytes("../files/test_simple.json")
        AlterVM.side_effect = IncorrectVMException()
        res = RESTAlterVM("1", "1")
        self.assertEqual(res, "Error modifying resources: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.Reconfigure")
    @patch("bottle.request")
    def test_Reconfigure(self, bottle_request, Reconfigure):
        """Test REST Reconfigure."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.body = BytesIO(b"radl")
        bottle_request.params = {'vm_list': '1,2'}

        Reconfigure.return_value = ""

        res = RESTReconfigureInfrastructure("1")
        self.assertEqual(res, "")

        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass"),
                                  "Content-Type": "application/json"}
        bottle_request.body = read_file_as_bytes("../files/test_simple.json")

        res = RESTReconfigureInfrastructure("1")
        self.assertEqual(res, "")

        bottle_request.body = read_file_as_bytes("../files/test_simple.json")
        Reconfigure.side_effect = DeletedInfrastructureException()
        res = RESTReconfigureInfrastructure("1")
        self.assertEqual(res, "Error reconfiguring infrastructure: Deleted infrastructure.")

        bottle_request.body = read_file_as_bytes("../files/test_simple.json")
        Reconfigure.side_effect = IncorrectInfrastructureException()
        res = RESTReconfigureInfrastructure("1")
        self.assertEqual(res, "Error reconfiguring infrastructure: Invalid infrastructure ID or access not granted.")

        bottle_request.body = read_file_as_bytes("../files/test_simple.json")
        Reconfigure.side_effect = UnauthorizedUserException()
        res = RESTReconfigureInfrastructure("1")
        self.assertEqual(res, "Error reconfiguring infrastructure: Access to this infrastructure not granted.")

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

        StartInfrastructure.side_effect = DeletedInfrastructureException()
        res = RESTStartInfrastructure("1")
        self.assertEqual(res, "Error starting infrastructure: Deleted infrastructure.")

        StartInfrastructure.side_effect = IncorrectInfrastructureException()
        res = RESTStartInfrastructure("1")
        self.assertEqual(res, "Error starting infrastructure: Invalid infrastructure ID or access not granted.")

        StartInfrastructure.side_effect = UnauthorizedUserException()
        res = RESTStartInfrastructure("1")
        self.assertEqual(res, "Error starting infrastructure: Access to this infrastructure not granted.")

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

        StopInfrastructure.side_effect = DeletedInfrastructureException()
        res = RESTStopInfrastructure("1")
        self.assertEqual(res, "Error stopping infrastructure: Deleted infrastructure.")

        StopInfrastructure.side_effect = IncorrectInfrastructureException()
        res = RESTStopInfrastructure("1")
        self.assertEqual(res, "Error stopping infrastructure: Invalid infrastructure ID or access not granted.")

        StopInfrastructure.side_effect = UnauthorizedUserException()
        res = RESTStopInfrastructure("1")
        self.assertEqual(res, "Error stopping infrastructure: Access to this infrastructure not granted.")

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

        StartVM.side_effect = DeletedInfrastructureException()
        res = RESTStartVM("1", "1")
        self.assertEqual(res, "Error starting VM: Deleted infrastructure.")

        StartVM.side_effect = IncorrectInfrastructureException()
        res = RESTStartVM("1", "1")
        self.assertEqual(res, "Error starting VM: Invalid infrastructure ID or access not granted.")

        StartVM.side_effect = UnauthorizedUserException()
        res = RESTStartVM("1", "1")
        self.assertEqual(res, "Error starting VM: Access to this infrastructure not granted.")

        StartVM.side_effect = DeletedVMException()
        res = RESTStartVM("1", "1")
        self.assertEqual(res, "Error starting VM: Deleted VM.")

        StartVM.side_effect = IncorrectVMException()
        res = RESTStartVM("1", "1")
        self.assertEqual(res, "Error starting VM: Invalid VM ID")

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

        StopVM.side_effect = DeletedInfrastructureException()
        res = RESTStopVM("1", "1")
        self.assertEqual(res, "Error stopping VM: Deleted infrastructure.")

        StopVM.side_effect = IncorrectInfrastructureException()
        res = RESTStopVM("1", "1")
        self.assertEqual(res, "Error stopping VM: Invalid infrastructure ID or access not granted.")

        StopVM.side_effect = UnauthorizedUserException()
        res = RESTStopVM("1", "1")
        self.assertEqual(res, "Error stopping VM: Access to this infrastructure not granted.")

        StopVM.side_effect = DeletedVMException()
        res = RESTStopVM("1", "1")
        self.assertEqual(res, "Error stopping VM: Deleted VM.")

        StopVM.side_effect = IncorrectVMException()
        res = RESTStopVM("1", "1")
        self.assertEqual(res, "Error stopping VM: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.RebootVM")
    @patch("bottle.request")
    def test_RebootVM(self, bottle_request, StopVM):
        """Test REST RebootVM."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        StopVM.return_value = ""

        res = RESTRebootVM("1", "1")
        self.assertEqual(res, "")

        StopVM.side_effect = DeletedInfrastructureException()
        res = RESTRebootVM("1", "1")
        self.assertEqual(res, "Error rebooting VM: Deleted infrastructure.")

        StopVM.side_effect = IncorrectInfrastructureException()
        res = RESTRebootVM("1", "1")
        self.assertEqual(res, "Error rebooting VM: Invalid infrastructure ID or access not granted.")

        StopVM.side_effect = UnauthorizedUserException()
        res = RESTRebootVM("1", "1")
        self.assertEqual(res, "Error rebooting VM: Access to this infrastructure not granted.")

        StopVM.side_effect = DeletedVMException()
        res = RESTRebootVM("1", "1")
        self.assertEqual(res, "Error rebooting VM: Deleted VM.")

        StopVM.side_effect = IncorrectVMException()
        res = RESTRebootVM("1", "1")
        self.assertEqual(res, "Error rebooting VM: Invalid VM ID")

    def test_GeVersion(self):
        res = RESTGeVersion()
        self.assertEqual(res, version)

    @patch("IM.InfrastructureManager.InfrastructureManager.CreateDiskSnapshot")
    @patch("bottle.request")
    def test_CreateDiskSnapshot(self, bottle_request, CreateDiskSnapshot):
        """Test REST StopVM."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        bottle_request.params = {'image_name': 'image_url', 'auto_delete': 'yes'}
        CreateDiskSnapshot.return_value = "one://server.com/image_url"

        res = RESTCreateDiskSnapshot("1", "1", 0)
        self.assertEqual(res, "one://server.com/image_url")

        CreateDiskSnapshot.side_effect = DeletedInfrastructureException()
        res = RESTCreateDiskSnapshot("1", "1", 0)
        self.assertEqual(res, "Error creating snapshot: Deleted infrastructure.")

        CreateDiskSnapshot.side_effect = IncorrectInfrastructureException()
        res = RESTCreateDiskSnapshot("1", "1", 0)
        self.assertEqual(res, "Error creating snapshot: Invalid infrastructure ID or access not granted.")

        CreateDiskSnapshot.side_effect = UnauthorizedUserException()
        res = RESTCreateDiskSnapshot("1", "1", 0)
        self.assertEqual(res, "Error creating snapshot: Access to this infrastructure not granted.")

        CreateDiskSnapshot.side_effect = DeletedVMException()
        res = RESTCreateDiskSnapshot("1", "1", 0)
        self.assertEqual(res, "Error creating snapshot: Deleted VM.")

        CreateDiskSnapshot.side_effect = IncorrectVMException()
        res = RESTCreateDiskSnapshot("1", "1", 0)
        self.assertEqual(res, "Error creating snapshot: Invalid VM ID")

    @patch("IM.InfrastructureManager.InfrastructureManager.ExportInfrastructure")
    @patch("bottle.request")
    def test_ExportInfrastructure(self, bottle_request, ExportInfrastructure):
        """Test REST StopInfrastructure."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}

        ExportInfrastructure.return_value = "strinf"

        res = RESTGetInfrastructureProperty("1", "data")
        self.assertEqual(res, '{"data": "strinf"}')

    @patch("IM.InfrastructureManager.InfrastructureManager.ImportInfrastructure")
    @patch("bottle.request")
    def test_ImportInfrastructure(self, bottle_request, ImportInfrastructure):
        """Test REST StopInfrastructure."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}

        ImportInfrastructure.return_value = "newid"

        res = RESTImportInfrastructure()
        self.assertEqual(res, "http://imserver.com/infrastructures/newid")

    @patch("IM.REST.get_media_type")
    def test_return_error(self, get_media_type):
        get_media_type.return_value = ["application/json"]
        msg = return_error(400, "Error msg.")
        res = json.loads(msg)
        self.assertEqual(res, {"message": "Error msg.", "code": 400})
        get_media_type.return_value = "text/html"
        msg = return_error(400, "Error msg.")
        self.assertEqual(msg, ('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html>\n    <head>\n'
                               '        <title>Error 400.</title>\n    </head>\n    <body>\n        '
                               '<h1>Code: 400.</h1>\n        <h1>Message: Error msg.</h1>\n    </body>\n</html>\n'))
        get_media_type.return_value = "text/plain"
        msg = return_error(400, "Error msg.")
        self.assertEqual(msg, "Error msg.")

    @patch("IM.REST.get_media_type")
    def test_format_output(self, get_media_type):
        get_media_type.return_value = ["application/json"]
        radl = parse_radl("system test (cpu.count = 1)")
        info = format_output(radl)
        info = json.loads(info)
        self.assertEqual(info, [{"cpu.count": 1, "class": "system", "id": "test"}])
        info = format_output(radl, field_name="radl")
        info = json.loads(info)
        self.assertEqual(info, {"radl": [{"cpu.count": 1, "class": "system", "id": "test"}]})

        radl = parse_radl("system test ( disk.0.applications contains (name='test'))")
        res = list(radl.systems[0].props.values())[0]
        info = format_output(res, field_name="cont")
        info = json.loads(info)
        self.assertEqual(info, {"cont": {"test": {"name": "test"}}})

        info = format_output(["1", "2"])
        info = json.loads(info)
        self.assertEqual(info, ["1", "2"])

        get_media_type.return_value = ["text/*"]
        info = format_output(["1", "2"], field_name="cont", default_type="application/json")
        info = json.loads(info)
        self.assertEqual(info, {"cont": ["1", "2"]})
        info = format_output(["1", "2"])
        self.assertEqual(info, '1\n2')

        info = format_output(u'contmsg\xe1', field_name="contmsg", default_type="text/plain")
        self.assertEqual(info, u'contmsg\xe1')

        get_media_type.return_value = ["application/zip"]
        info = format_output(["1", "2"])
        self.assertEqual(info, 'Unsupported Accept Media Types: application/zip')

    @patch("IM.VirtualMachine.SSH")
    @patch("IM.InfrastructureManager.InfrastructureManager.get_infrastructure")
    @patch("IM.InfrastructureManager.InfrastructureManager.check_auth_data")
    @patch("bottle.request")
    def test_commands(self, bottle_request, check_auth_data, get_infrastructure, SSH):
        """Test REST StopInfrastructure."""
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}

        inf = InfrastructureInfo()
        inf.id = "1"
        inf.auth = Authentication([{'type': 'InfrastructureManager', 'username': 'user', 'password': 'pass'}])
        get_infrastructure.return_value = inf

        bottle_request.params = {'step': '1'}
        res = RESTGetVMProperty("1", "1", "command")
        auth_str = "Authorization: type = InfrastructureManager; username = user; password = pass"
        url = "http://imserver.com/infrastructures/1/vms/1/command?step=2"
        expected_res = """
                res="wait"
                while [ "$res" == "wait" ]
                do
                  res=`curl --insecure -s -H "%s" -H "Accept: text/plain" %s`
                  if [ "$res" != "wait" ]
                  then
                    eval "$res"
                  else
                    sleep 20
                  fi
                done""" % (auth_str, url)
        self.assertEqual(res, expected_res)

        inf.auth = Authentication([{'type': 'InfrastructureManager', 'token': 'token'}])
        res = RESTGetVMProperty("1", "1", "command")
        auth_str = "Authorization: type = InfrastructureManager; token = token"
        url = "http://imserver.com/infrastructures/1/vms/1/command?step=2"
        expected_res = """
                res="wait"
                while [ "$res" == "wait" ]
                do
                  res=`curl --insecure -s -H "%s" -H "Accept: text/plain" %s`
                  if [ "$res" != "wait" ]
                  then
                    eval "$res"
                  else
                    sleep 20
                  fi
                done""" % (auth_str, url)
        self.assertEqual(res, expected_res)

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
        bottle_request.params = {'step': '2'}
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

        res = RESTGetVMProperty("1", "0", "command")
        expected_res = "true"
        self.assertEqual(res, expected_res)

        bottle_request.params = {'step': '2'}
        res = RESTGetVMProperty("1", "1", "command")
        expected_res = "true"
        self.assertEqual(res, expected_res)

        # in VM not connected to the Master VM
        res = RESTGetVMProperty("1", "2", "command")
        expected_res = ('sshpass -pyoyoyo ssh -N -R 20002:localhost:22 -p 22 -o "UserKnownHostsFile=/dev/null"'
                        ' -o "StrictHostKeyChecking=no" ubuntu@8.8.8.8 &')
        self.assertEqual(res, expected_res)


if __name__ == "__main__":
    unittest.main()
