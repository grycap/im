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


from IM.connectors.OpenStack import OpenStackCloudConnector
from IM.AppDB import AppDB
from IM.auth import Authentication
from IM.CloudInfo import CloudInfo
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class EGICloudConnector(OpenStackCloudConnector):
    """
    Cloud Launcher to EGI using LibCloud
    """

    type = "EGI"
    """str with the name of the provider."""

    def __init__(self, cloud_info, inf):
        self.egi_auth = None
        OpenStackCloudConnector.__init__(self, cloud_info, inf)

    def get_driver(self, auth_data):
        """
        Get the driver from the auth data

        Arguments:
                - auth(Authentication): parsed authentication tokens.

        Returns: a :py:class:`libcloud.compute.base.NodeDriver` or None in case of error
        """
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            raise Exception("No auth data has been specified to EGI.")
        else:
            auth = auths[0]

        if self.driver and self.egi_auth.compare(auth_data, self.type, self.cloud.server):
            return self.driver
        else:
            self.egi_auth = auth_data

            if 'host' in auth and 'vo' in auth and 'token' in auth:
                ost_auth = {'id': auth['id'], 'type': 'OpenStack', 'username': 'egi.eu', 'tenant': 'openid',
                            'password': auth['token'], 'auth_version': '3.x_oidc_access_token', 'vo': auth['vo']}
                site_id = AppDB.get_site_id(auth["host"], stype="openstack")
                site_url = AppDB.get_site_url(site_id)
                if not site_url:
                    raise Exception("Invalid site name '%s'. Not found at AppDB." % auth['host'])
                ost_auth['host'] = site_url
                projects = AppDB.get_project_ids(site_id)
                # If the VO does not appear in the project IDs
                if auth['vo'] in projects:
                    ost_auth['domain'] = projects[auth['vo']]
                else:
                    # let's use the VO name directly
                    ost_auth['domain'] = auth['vo']

                if 'api_version' in auth:
                    ost_auth['api_version'] = auth['api_version']

                new_auth = Authentication([ost_auth])

                orig_cloud = self.cloud
                self.cloud = CloudInfo.get_cloud_list(new_auth)[0]
                self.type = OpenStackCloudConnector.type
                driver = OpenStackCloudConnector.get_driver(self, new_auth)
                self.type = EGICloudConnector.type
                self.cloud = orig_cloud

                self.driver = driver
                return driver
            else:
                self.log_error("No correct auth data has been specified to EGI: host, vo, and token")
                raise Exception("No correct auth data has been specified to EG: host, vo, and token")

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        src_host = url[1].split(':')[0]

        if protocol in ["ost", "appdb"] and self.cloud.server and not self.cloud.protocol:
            site_host = ""
            if protocol == "ost":
                site_url = AppDB.get_site_url(self.cloud.server)
                if site_url:
                    site_host = urlparse(site_url)[1].split(':')[0]

            if ((protocol == "ost" and site_host == src_host) or
                    (protocol == "appdb" and src_host == self.cloud.server)):
                driver = self.get_driver(auth_data)

                res_system = radl_system.clone()
                instance_type = self.get_instance_type(driver, res_system)
                self.update_system_info_from_instance(res_system, instance_type)

                username = res_system.getValue('disk.0.os.credentials.username')
                if not username:
                    res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)

                return res_system
            else:
                return None
        else:
            return None

    @staticmethod
    def _get_tenant_id(driver, auth):
        """
        Workaround function to get tenant id from tenant name
        """
        if 'auth_version' in auth and auth['auth_version'] == '3.x_oidc_access_token':
            return auth['domain']
        else:
            if 'tenant_id' in auth:
                return auth['tenant_id']
            else:
                return auth['tenant']

        return None
