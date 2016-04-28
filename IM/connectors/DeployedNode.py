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

import time
from IM.VirtualMachine import VirtualMachine
from CloudConnector import CloudConnector


class DeployedNodeCloudConnector(CloudConnector):
    """
    Cloud Launcher to manage existing running nodes.
    The connector does nothing, but enable to integrate these nodes into the contextualization.
    """

    type = "DeployedNode"
    """str with the name of the provider."""

    def concreteSystem(self, radl_system, auth_data):
        # we must check that the RADL has this information:
        # At least one IP, username, password or private_key
        ip = radl_system.getValue("net_interface.0.ip")
        user = radl_system.getValue("disk.0.os.credentials.username")
        passwd = radl_system.getValue("disk.0.os.credentials.password")
        priv_key = radl_system.getValue("disk.0.os.credentials.private_key")

        if ip and user and (passwd or priv_key):
            res_system = radl_system.clone()
            return [res_system]
        else:
            return []

    def updateVMInfo(self, vm, auth_data):
        return (True, vm)

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        res = []
        for _ in range(num_vm):
            now = str(int(time.time() * 100))
            vm = VirtualMachine(inf, now, self.cloud,
                                requested_radl, requested_radl)
            vm.info.systems[0].setValue('provider.type', self.type)
            vm.state = VirtualMachine.RUNNING
            res.append((True, vm))

        return res

    def finalize(self, vm, auth_data):
        return (True, "")

    def stop(self, vm, auth_data):
        return (False, "Operation not supported")

    def start(self, vm, auth_data):
        return (False, "Operation not supported")

    def alterVM(self, vm, radl, auth_data):
        return (False, "Not supported")
