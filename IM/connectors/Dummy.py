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
from .CloudConnector import CloudConnector
from radl.radl import Feature


class DummyCloudConnector(CloudConnector):
    """
    Cloud Launcher to test the IM.
    The connector does nothing.
    """

    type = "Dummy"
    """str with the name of the provider."""

    def concreteSystem(self, radl_system, auth_data):
        res_system = radl_system.clone()
        return [res_system]

    def updateVMInfo(self, vm, auth_data):
        return (True, vm)

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        res = []
        for _ in range(num_vm):
            now = str(int(time.time() * 100))
            vm = VirtualMachine(inf, now, self.cloud,
                                requested_radl, requested_radl)
            inf.add_vm(vm)

            vm.info.systems[0].setValue('provider.type', self.type)
            vm.state = VirtualMachine.RUNNING

            vm.info.systems[0].setValue("net_interface.0.ip", "10.0.0.1")
            vm.info.systems[0].setValue(
                "disk.0.os.credentials.username", "username")
            vm.info.systems[0].setValue(
                "disk.0.os.credentials.password", "password")

            res.append((True, vm))

        return res

    def finalize(self, vm, last, auth_data):
        return (True, "")

    def stop(self, vm, auth_data):
        vm.state = VirtualMachine.STOPPED
        return (True, "")

    def start(self, vm, auth_data):
        vm.state = VirtualMachine.RUNNING
        return (True, "")

    def reboot(self, vm, auth_data):
        return (True, "")

    def alterVM(self, vm, radl, auth_data):
        if not radl.systems:
            return (True, "")
        system = radl.systems[0]

        new_cpu = system.getValue('cpu.count')
        new_memory = system.getFeature('memory.size').getValue('M')

        vm.info.systems[0].setValue('cpu.count', new_cpu)
        vm.info.systems[0].addFeature(
            Feature("memory.size", "=", new_memory, 'M'), conflict="other", missing="other")

        return (True, "")

    def create_snapshot(self, vm, disk_num, image_name, auto_delete, auth_data):
        new_url = "mock0://linux.for.ev.er/%s" % image_name
        if auto_delete:
            vm.inf.snapshots.append(new_url)
        return (True, new_url)

    def delete_image(self, image_url, auth_data):
        return (True, "")

    def list_images(self, auth_data, filters=None):
        return [{"uri": "mock0://linux.for.ev.er/image1", "name": "Image Name1"},
                {"uri": "mock0://linux.for.ev.er/image2", "name": "Image Name2"}]

    def get_quotas(self, auth_data):
        return {"cores": {"used": 1, "limit": 10},
                "ram": {"used": 1, "limit": 10},
                "instances": {"used": 1, "limit": 10},
                "floating_ips": {"used": 1, "limit": 10},
                "security_groups": {"used": 1, "limit": 10}}
