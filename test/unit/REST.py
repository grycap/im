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

from IM.auth import Authentication
from IM.REST import (RESTDestroyInfrastructure,
                     RESTGetInfrastructureInfo,
                     RESTGetInfrastructureProperty,
                     RESTGetInfrastructureList,
                     RESTCreateInfrastructure,
                     RESTGetVMInfo)


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
                                                    "username = user; password = pass")}
        GetInfrastructureList.return_value = ["1", "2"]
        res = RESTGetInfrastructureList()
        self.assertEqual(res, ("http://imserver.com/infrastructures/1\n"
                               "http://imserver.com/infrastructures/2"))

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
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
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
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
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

    @patch("IM.InfrastructureManager.InfrastructureManager.GetVMInfo")
    @patch("bottle.request")
    def test_GetVMInfo(self, bottle_request, GetVMInfo):
        """Test REST GetVMInfo."""
        bottle_request.environ = {'HTTP_HOST': 'imserver.com'}
        bottle_request.return_value = MagicMock()
        bottle_request.headers = {"AUTHORIZATION": ("type = InfrastructureManager; username = user; password = pass\n"
                                                    "id = one; type = OpenNebula; host = onedock.i3m.upv.es:2633; "
                                                    "username = user; password = pass")}
        bottle_request.body.read.return_value = "radl"
        
        GetVMInfo.return_value = "radl_data"

        res = RESTGetVMInfo("1", "1")
        self.assertEqual(res, "radl_data")

if __name__ == "__main__":
    unittest.main()
