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
from IM.config import Config
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

                auth_url = "iam.%s.prod-cloud-ocb.orange-business.com" % region

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

    def setVolumesInfo(self, vm, node):
        try:
            cont = 1
            if 'volumes_attached' in node.extra and node.extra['volumes_attached']:
                if 'availability_zone' in node.extra and node.extra['availability_zone']:
                    region = node.extra['availability_zone'][:-1]
                else:
                    region = self.REGIONS[0]
                for vol_info in node.extra['volumes_attached']:
                    vol_id = vol_info['id']
                    self.log_debug("Getting Volume info %s" % vol_id)
                    volume = node.driver.ex_get_volume(vol_id)
                    disk_size = None
                    if vm.info.systems[0].getValue("disk." + str(cont) + ".size"):
                        disk_size = vm.info.systems[0].getFeature("disk." + str(cont) + ".size").getValue('G')
                    if disk_size and disk_size != volume.size:
                        self.log_warn("Volume ID %s does not have the expected size %s != %s" % (vol_id,
                                                                                                 volume.size,
                                                                                                 disk_size))
                        continue
                    vm.info.systems[0].setValue("disk." + str(cont) + ".size", volume.size, 'G')

                    disk_url = vm.info.systems[0].getValue("disk." + str(cont) + ".image.url")
                    if disk_url and os.path.basename(disk_url) != vol_id:
                        self.log_warn("Volume does not have the expected id %s != %s" % (vol_id,
                                                                                         os.path.basename(disk_url)))
                    vm.info.systems[0].setValue("disk." + str(cont) + ".image.url", "ora://%s/%s" % (region,
                                                                                                     volume.id))
                    if 'attachments' in volume.extra and volume.extra['attachments']:
                        vm.info.systems[0].setValue("disk." + str(cont) + ".device",
                                                    os.path.basename(volume.extra['attachments'][0]['device']))
                    cont += 1
        except Exception as ex:
            self.log_warn("Error getting volume info: %s" % str(ex))

    def create_snapshot(self, vm, disk_num, image_name, auto_delete, auth_data):
        raise Exception("Not supported.")

    def delete_image(self, image_url, auth_data):
        raise Exception("Not supported.")
