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

if __name__ == "__main__":
    unittest.main()
