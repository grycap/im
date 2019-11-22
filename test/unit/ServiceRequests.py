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

import unittest
from mock import patch


class TestServiceRequests(unittest.TestCase):
    """
    Class to test the ServiceRequests module
    """

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_add_resource(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.ADD_RESOURCE,
                                                              ("", "", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_alter_vm(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.ALTER_VM,
                                                              ("", "", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_create(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.CREATE_INFRASTRUCTURE,
                                                              ("", "", True))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_destroy(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.DESTROY_INFRASTRUCTURE,
                                                              ("", "", False, True))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_export(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.EXPORT_INFRASTRUCTURE,
                                                              ("", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_cont_msg(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.
                                                              IMBaseRequest.GET_INFRASTRUCTURE_CONT_MSG,
                                                              ("", "", False))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_getinfo(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.GET_INFRASTRUCTURE_INFO,
                                                              ("", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_list(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.GET_INFRASTRUCTURE_LIST,
                                                              ("", ".*"))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_getradl(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.GET_INFRASTRUCTURE_RADL,
                                                              ("", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_getstate(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.GET_INFRASTRUCTURE_STATE,
                                                              ("", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_vm_contmsg(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.GET_VM_CONT_MSG,
                                                              ("", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_vm_info(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.GET_VM_INFO,
                                                              ("", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_vm_prop(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.GET_VM_PROPERTY,
                                                              ("", "", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_import(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.IMPORT_INFRASTRUCTURE,
                                                              ("", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_reconfigure(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.RECONFIGURE,
                                                              ("", "", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_remove(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.REMOVE_RESOURCE,
                                                              ("", "", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_start(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.START_INFRASTRUCTURE,
                                                              ("", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_stop(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.STOP_INFRASTRUCTURE,
                                                              ("", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_vm_start(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.START_VM,
                                                              ("", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_vm_stop(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.STOP_VM,
                                                              ("", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_vm_reboot(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.REBOOT_VM,
                                                              ("", "", ""))
        req._call_function()

    @patch('IM.InfrastructureManager.InfrastructureManager')
    def test_version(self, inflist):
        import IM.ServiceRequests
        req = IM.ServiceRequests.IMBaseRequest.create_request(IM.ServiceRequests.IMBaseRequest.GET_VERSION)
        req._call_function()


if __name__ == '__main__':
    unittest.main()
