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
from IM.REST import app


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
                                     "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                     "username = user; password = pass")}
        CreateInfrastructure.return_value = "1"

        res = self.client.post('/infrastructures', headers=headers, data=BytesIO(b"radl"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1")

        res = self.client.post('/infrastructures?async=yes', headers=headers, data=BytesIO(b"radl"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1")

        headers["Content-Type"] = "application/json"
        res = self.client.post('/infrastructures', headers=headers, data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1")

        headers["Content-Type"] = "text/yaml"
        res = self.client.post('/infrastructures', headers=headers, data=read_file_as_bytes("../files/tosca_simple.yml"))
        self.assertEqual(res.text, "http://localhost/infrastructures/1")

        headers["Content-Type"] = "application/json"
        # Test the dry_run option to get the estimation of the resources
        res = self.client.post('/infrastructures?dry_run=yes', headers=headers, data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.json, {"one": {"cloudType": "OpenNebula",
                                            "cloudEndpoint": "http://onedock.i3m.upv.es:2633",
                                            "compute": [{"cpuCores": 1, "memoryInMegabytes": 1024},
                                                        {"cpuCores": 1, "memoryInMegabytes": 1024}], "storage": []}})

        headers["Content-Type"] = "application/json"
        CreateInfrastructure.side_effect = InvaliddUserException()
        res = self.client.post('/infrastructures', headers=headers, data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error Getting Inf. info: Invalid InfrastructureManager credentials")

        CreateInfrastructure.side_effect = UnauthorizedUserException()
        res = self.client.post('/infrastructures', headers=headers, data=read_file_as_bytes("../files/test_simple.json"))
        self.assertEqual(res.text, "Error Creating Inf.: Access to this infrastructure not granted.")

if __name__ == "__main__":
    unittest.main()
