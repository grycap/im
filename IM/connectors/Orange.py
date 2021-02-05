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


import os.path
import requests
from IM.connectors.OpenStack import OpenStackCloudConnector
from IM.VirtualMachine import VirtualMachine
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

try:
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
except Exception as ex:
    print("WARN: libcloud library not correctly installed. OpenStackCloudConnector will not work!.")
    print(ex)


class OrangeCloudConnector(OpenStackCloudConnector):
    """
    Cloud Launcher to Orange using LibCloud (Needs version 0.16.0 or higher version)
    """

    type = "Orange"
    """str with the name of the provider."""
    REGIONS = ['eu-west-0', 'eu-west-1', 'na-east-0']
    """ Current available regions """

    def __init__(self, cloud_info, inf):
        # Patch to solve SSL error
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'
        OpenStackCloudConnector.__init__(self, cloud_info, inf)

    def get_driver(self, auth_data):
        """
        Get the driver from the auth data

        Arguments:
                - auth(Authentication): parsed authentication tokens.

        Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise Exception("No auth data has been specified to Orange.")
        else:
            auth = auths[0]

        if self.driver and self.auth.compare(auth_data, self.type):
            return self.driver
        else:
            self.auth = auth_data

            if 'username' in auth and 'password' in auth and 'domain' in auth:
                username = auth['username']
                password = auth['password']
                domain = auth['domain']

                region = tenant = self.REGIONS[0]
                if 'tenant' in auth:
                    tenant = auth['tenant']
                elif 'region' in auth:
                    tenant = auth['region']

                if 'region' in auth:
                    region = auth['region']

                auth_url = "https://iam.%s.prod-cloud-ocb.orange-business.com" % region

                cls = get_driver(Provider.OPENSTACK)
                driver = cls(username, password,
                             ex_tenant_name=tenant,
                             ex_force_auth_url=auth_url,
                             api_version='2.0',
                             auth_version='3.x_password',
                             ex_force_service_region=region,
                             ex_domain_name=domain)

                self.driver = driver
                return driver
            else:
                self.log_error(
                    "No correct auth data has been specified to Orange: username, password, domain, tenant and region")
                raise Exception(
                    "No correct auth data has been specified to Orange: username, password, domain, tenant and region")

    def guess_instance_type_gpu(self, size):
        """Try to guess if this NodeSize has GPU support"""
        try:
            extra_specs = size.driver.ex_get_size_extra_specs(size.id)
            if 'ecs:performancetype' in extra_specs and extra_specs['ecs:performancetype'] == 'gpu':
                return True
        except Exception:
            self.log_exception("Error trying to get flavor extra_specs.")
        return False

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]

        if protocol == "ora":
            driver = self.get_driver(auth_data)

            res_system = radl_system.clone()
            instance_type = self.get_instance_type(driver.list_sizes(), res_system)
            self.update_system_info_from_instance(res_system, instance_type)

            username = res_system.getValue('disk.0.os.credentials.username')
            if not username:
                res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

            return res_system
        else:
            return None

    @staticmethod
    def get_volumes(driver, image, radl):
        """
        Create the required volumes (in the RADL) for the VM.

        Arguments:
           - vm(:py:class:`IM.VirtualMachine`): VM to modify.
        """
        system = radl.systems[0]
        res = []
        cont = 1
        while (system.getValue("disk." + str(cont) + ".size") or
                system.getValue("disk." + str(cont) + ".image.url")):
            disk_url = system.getValue("disk." + str(cont) + ".image.url")

            if disk_url:
                volume = driver.ex_get_volume(os.path.basename(disk_url))
                disk = {
                    'boot_index': -1,
                    'source_type': "volume",
                    'delete_on_termination': False,
                    'destination_type': "volume",
                    'uuid': volume.id
                }
            else:
                disk_size = system.getFeature("disk." + str(cont) + ".size").getValue('G')
                # Min size is 10 GB
                if disk_size < 10:
                    disk_size = 10

                disk = {
                    'boot_index': -1,
                    'source_type': "blank",
                    'destination_type': "volume",
                    'delete_on_termination': True,
                    'volume_size': disk_size
                }

            res.append(disk)
            cont += 1

        return res

    def updateVMInfo(self, vm, auth_data):
        node = self.get_node_with_id(vm.id, auth_data)
        if node:
            vm.state = self.VM_STATE_MAP.get(node.state, VirtualMachine.UNKNOWN)

            if vm.state == VirtualMachine.FAILED:
                if 'fault' in node.extra and node.extra['fault']:
                    error_msg = str(node.extra['fault']['message'])
                    if error_msg not in self.error_messages:
                        self.error_messages += error_msg

            try:
                flavorId = node.extra['flavorId']
                instance_type = node.driver.ex_get_size(flavorId)
                self.update_system_info_from_instance(vm.info.systems[0], instance_type)
                if 'availability_zone' in node.extra:
                    vm.info.systems[0].setValue('availability_zone', node.extra['availability_zone'])
            except Exception as ex:
                self.log_warn("Error updating VM info from flavor ID: %s" % str(ex))

            self.addRouterInstance(vm, node.driver)
            self.setIPsFromInstance(vm, node)
            self.setVolumesInfo(vm, node)
        else:
            self.log_warn("Error updating the instance %s. VM not found." % vm.id)
            return (False, "Error updating the instance %s. VM not found." % vm.id)

        return (True, vm)

    def setVolumesInfo(self, vm, node):
        try:
            if 'volumes_attached' in node.extra and node.extra['volumes_attached']:
                for vol_info in node.extra['volumes_attached']:
                    vol_id = vol_info['id']
                    self.log_debug("Getting Volume info %s" % vol_id)
                    volume = node.driver.ex_get_volume(vol_id)

                    if 'attachments' in volume.extra and volume.extra['attachments']:
                        disk_device = volume.extra['attachments'][0]['device']
                        cont = ord(disk_device[-1:]) - 97

                        disk_size = None
                        if vm.info.systems[0].getValue("disk." + str(cont) + ".size"):
                            disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
                        if disk_size and disk_size != volume.size:
                            self.log_warn("Volume ID %s without the expected size %s != %s" % (vol_id,
                                                                                               volume.size,
                                                                                               disk_size))
                            continue

                        disk_url = vm.info.systems[0].getValue("disk." + str(cont) + ".image.url")
                        if disk_url and os.path.basename(disk_url) != vol_id:
                            self.log_warn("Volume without the expected id %s != %s" % (vol_id,
                                                                                       os.path.basename(disk_url)))
                            continue

                        vm.info.systems[0].setValue("disk." + str(cont) + ".size", volume.size, 'G')
                        if cont != 0:
                            region = volume.extra['location'][:-1]
                            vm.info.systems[0].setValue("disk." + str(cont) + ".image.url", "ora://%s/%s" % (region,
                                                                                                             volume.id))
                            vm.info.systems[0].setValue("disk." + str(cont) + ".device", os.path.basename(disk_device))

        except Exception as ex:
            self.log_warn("Error getting volume info: %s" % str(ex))

    def create_snapshot(self, vm, disk_num, image_name, auto_delete, auth_data):
        raise Exception("Not supported.")

    def delete_image(self, image_url, auth_data):
        raise Exception("Not supported.")

    def list_images(self, auth_data, filters=None):
        driver = self.get_driver(auth_data)
        auth = auth_data.getAuthInfo(self.type, self.cloud.server)[0]
        if 'region' in auth:
            region = auth['region']
        else:
            region = self.REGIONS[0]

        images = []
        for image in driver.list_images():
            images.append({"uri": "ora://%s/%s" % (region, image.id), "name": image.name})
        return images
